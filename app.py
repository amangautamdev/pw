from flask import Flask, request, jsonify
from pydantic import BaseModel
import httpx
import re
import base64
from urllib.parse import urlparse
import xmltodict
import asyncio

app = Flask(name)

class MPDInfo(BaseModel):
    mpd_link: str
    keys: str
    pssh: str

class Penpencil:
    otp_url = "https://api.penpencil.xyz/v1/videos/get-otp?key="
    def init(self, token: str):
        self.token = token
        self.headers = {
            "Host": "api.penpencil.xyz",
            "content-type": "application/json",
            "authorization": f"Bearer {token}",
            "client-version": "11",
            "user-agent": "Mozilla/5.0 (Linux; Android 10; PACM00) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.98 Mobile Safari/537.36",
            "Client-Type": "WEB",
            "accept-encoding": "gzip",
        }

    @staticmethod
    def encode_utf16_hex(input_string: str) -> str:
        hex_string = ''.join(f"{ord(char):04x}" for char in input_string)
        return hex_string

    def get_otp_key(self, kid: str):
        xor_bytes = bytes([ord(kid[i]) ^ ord(self.token[i % len(self.token)]) for i in range(len(kid))])
        return base64.b64encode(xor_bytes).decode("utf-8")

    def get_key(self, otp: str):
        a = base64.b64decode(otp)
        c = [int(a[i]) for i in range(len(a))]
        return "".join([chr(c[j] ^ ord(self.token[j % len(self.token)])) for j in range(len(c))])

    async def get_keys(self, kid: str):
        otp_key = self.get_otp_key(kid)
        encoded_hex = self.encode_utf16_hex(otp_key)
        async with httpx.AsyncClient(headers=self.headers) as client:
            otp_url = f"{self.otp_url}{encoded_hex}&isEncoded=true"
            resp = await client.get(otp_url)
            otp_dict = resp.json()
            otp = otp_dict["data"]["otp"]
            key = self.get_key(otp)
            return f"{kid}:{key}"

async def get_pssh_kid(mpd_url: str, headers: dict = {}, cookies: dict = {}):
    async with httpx.AsyncClient() as client:
        res = await client.get(mpd_url, headers=headers, cookies=cookies)
        mpd_res = res.text
    matches = re.finditer("<cenc:pssh>(.*)</cenc:pssh>", mpd_res)
    pssh = next(matches).group(1)
    kid = re.findall(r'default_KID="([\S]+)"', mpd_res)[0].replace("-", "")
    return pssh, kid

@app.route("/mpd_info", methods=["GET"])
def get_mpd_info():
    mpd = request.args.get("mpd")
    token = request.args.get("token")
    
    if not mpd or not token:
        return jsonify({"error": "Missing mpd or token parameter"}), 400

    try:
        penpencil = Penpencil(token)
        pssh, kid = asyncio.run(get_pssh_kid(mpd))
        keys = asyncio.run(penpencil.get_keys(kid))
        
        return jsonify({
            "mpd_link": mpd,
            "keys": keys,
            "pssh": pssh
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if name == "main":
    app.run(host="0.0.0.0", port=8000)

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
from flask import Flask, jsonify, request
import uid_generator_pb2
from data_pb2 import AccountPersonalShowInfo
from google.protobuf.json_format import MessageToDict
import threading
import time

app = Flask(__name__)

# إعدادات ثابتة
key = "Yg&tc%DEuh6%Zc^8"
iv = "6oyZDr22E3ychjM%"
jwt_token = None
jwt_lock = threading.Lock()
freefire_version = "ob49"  # ضع النسخة التي تعمل حالياً

# استخراج التوكن من رابط ثابت
def get_jwt_token():
    global jwt_token
    url = "https://token-free.vercel.app/get?uid=3823924635&password=E6304F7F5103865FC221A1F309E07F04ABC95991CEB470EBF15B7E80045AD0EC"
    try:
        with jwt_lock:
            res = requests.get(url, timeout=10)
            if res.status_code == 200:
                data = res.json()
                jwt_token = data.get("token")
                print(f"[✅] Token Updated: {jwt_token[:30]}...")
                return jwt_token
    except Exception as e:
        print(f"[❌] Token fetch error: {e}")
    return None

def ensure_token():
    global jwt_token
    return jwt_token if jwt_token else get_jwt_token()

def token_updater():
    while True:
        get_jwt_token()
        time.sleep(300)

# تشفير AES
def encrypt_aes(hex_data, key, iv):
    cipher = AES.new(key.encode()[:16], AES.MODE_CBC, iv.encode()[:16])
    padded = pad(bytes.fromhex(hex_data), AES.block_size)
    return binascii.hexlify(cipher.encrypt(padded)).decode()

# تحديد رابط API حسب الدولة
def get_api_endpoint(region):
    endpoints = {
        "IND": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
        "default": "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
    }
    return endpoints.get(region.upper(), endpoints["default"])

# إرسال الطلب للـ API
def send_player_request(uid_hex, region):
    token = ensure_token()
    if not token:
        raise Exception("No token available")
    
    headers = {
        'Authorization': f'Bearer {token}',
        'User-Agent': 'Dalvik/2.1.0 (Linux; Android 9)',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': freefire_version,
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    response = requests.post(
        get_api_endpoint(region),
        headers=headers,
        data=bytes.fromhex(uid_hex),
        timeout=10
    )
    response.raise_for_status()
    return response.content.hex()

@app.route('/accinfo', methods=['GET'])
def accinfo():
    try:
        uid = request.args.get('uid')
        if not uid:
            return jsonify({"error": "Missing uid"}), 400

        region = request.args.get('region', 'default')
        custom_key = request.args.get('key', key)
        custom_iv = request.args.get('iv', iv)

        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        protobuf_data = message.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()

        encrypted = encrypt_aes(hex_data, custom_key, custom_iv)
        api_response = send_player_request(encrypted, region)

        msg = AccountPersonalShowInfo()
        msg.ParseFromString(bytes.fromhex(api_response))
        return jsonify(MessageToDict(msg))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/')
def home():
    return '🔹 Free Fire Player Info API 🔹', 200

if __name__ == '__main__':
    get_jwt_token()
    threading.Thread(target=token_updater, daemon=True).start()
    app.run(host="0.0.0.0", port=5552)
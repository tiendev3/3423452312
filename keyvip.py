import json
import hmac
import hashlib
import base64
from datetime import datetime
import requests

# URL của file vipkey.json (dạng txt): mỗi dòng key|dd-mm-yyyy
VIP_KEY_URL = "https://raw.githubusercontent.com/tiendev3/4746745645645645/refs/heads/main/keyvip.json"
SECRET_KEY = "super-secret-key-tiendev"  # có thể đổi hoặc lấy từ env nếu muốn bảo mật hơn

# Đọc file VIP key từ GitHub
def load_vip_keys():
    keys = {}
    try:
        response = requests.get(VIP_KEY_URL)
        if response.status_code == 200:
            lines = response.text.strip().splitlines()
            for line in lines:
                if '|' in line:
                    key, expiry_str = line.strip().split('|')
                    try:
                        expiry_date = datetime.strptime(expiry_str, "%d-%m-%Y")
                        keys[key] = expiry_date
                    except ValueError:
                        continue
    except:
        pass
    return keys

def encrypt_expiry(expiry_datetime):
    expiry_str = expiry_datetime.isoformat()
    return base64.b64encode(expiry_str.encode()).decode()

def decrypt_expiry(encrypted_str):
    try:
        decoded = base64.b64decode(encrypted_str.encode()).decode()
        return datetime.fromisoformat(decoded)
    except:
        return None

def generate_signature(key, encrypted_expiry):
    data = f"{key}|{encrypted_expiry}"
    return hmac.new(SECRET_KEY.encode(), data.encode(), hashlib.sha256).hexdigest()

def verify_signature(key_data):
    try:
        key = key_data['key']
        encrypted_expiry = key_data['expiry_encrypted']
        expected = generate_signature(key, encrypted_expiry)
        return hmac.compare_digest(expected, key_data.get('signature', ''))
    except:
        return False

def validate_vip_key(input_key):
    vip_keys = load_vip_keys()
    if input_key in vip_keys:
        expiry = vip_keys[input_key]
        if datetime.now() <= expiry:
            encrypted_expiry = encrypt_expiry(expiry)
            signature = generate_signature(input_key, encrypted_expiry)
            return {
                'key': input_key,
                'type': 'vip',
                'expiry_encrypted': encrypted_expiry,
                'signature': signature,
                'valid': True
            }
    return {'valid': False}

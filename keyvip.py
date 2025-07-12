import json
import hmac
import hashlib
import base64
from datetime import datetime

VIP_KEY_FILE = "vipkey.json"
SECRET_KEY = "super-secret-key-tiendev"  # giữ bí mật, có thể đổi thành chuỗi phức tạp hơn

# Đọc file vipkey.json định dạng: key|dd-mm-yyyy
def load_vip_keys():
    keys = {}
    try:
        with open(VIP_KEY_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                if '|' in line:
                    key, expiry_str = line.strip().split('|')
                    try:
                        expiry_date = datetime.strptime(expiry_str, "%d-%m-%Y")
                        keys[key] = expiry_date
                    except ValueError:
                        continue
    except FileNotFoundError:
        pass
    return keys

# Mã hóa thời gian expiry bằng base64
def encrypt_expiry(expiry_datetime):
    expiry_str = expiry_datetime.isoformat()
    encoded = base64.b64encode(expiry_str.encode()).decode()
    return encoded

# Giải mã expiry từ base64
def decrypt_expiry(encrypted_str):
    try:
        decoded = base64.b64decode(encrypted_str.encode()).decode()
        return datetime.fromisoformat(decoded)
    except:
        return None

# Tạo chữ ký bảo vệ cho key + expiry đã mã hóa
def generate_signature(key, encrypted_expiry):
    data = f"{key}|{encrypted_expiry}"
    return hmac.new(SECRET_KEY.encode(), data.encode(), hashlib.sha256).hexdigest()

# Kiểm tra chữ ký có đúng hay không (chống chỉnh sửa file key.json)
def verify_signature(key_data):
    try:
        key = key_data['key']
        encrypted_expiry = key_data['expiry_encrypted']
        expected_signature = generate_signature(key, encrypted_expiry)
        return hmac.compare_digest(expected_signature, key_data.get('signature', ''))
    except:
        return False

# Kiểm tra key người dùng nhập có hợp lệ không
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
                'valid': True
            }
    return {'valid': False}


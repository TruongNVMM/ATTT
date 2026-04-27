import os
import sys
import json
import base64
import ast

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from src.asymmetric.RSA.RSA import RSA

class Receiver:
    def __init__(self, private_key_r_path):
        """
        Khởi tạo Class Receiver với khóa
        - PriKey(R): Dùng cho khối Decryption 1 (Giải mã gói S&E Message bằng RSA)
        (Khóa PubKey(S) của Sender — dạng RSA — sẽ được trích xuất động trong bước Unpack)
        """
        self.rsa = RSA()
        
        # Đọc khóa Private Key (RSA) của Receiver
        if os.path.exists(private_key_r_path):
            self.pri_key_r = self._parse_rsa_pem(private_key_r_path)
        else:
            raise FileNotFoundError(f"File not found: {private_key_r_path}")

    def _parse_rsa_pem(self, pem_path):
        """Hàm đọc tuple (d, n) hoặc (e, n) của khóa RSA từ tệp PEM"""
        with open(pem_path, 'r', encoding='utf-8') as f:
            lines = f.read().strip().split('\n')
        b64_content = "".join([line for line in lines if not line.startswith('-----')])
        key_str = base64.b64decode(b64_content).decode('utf-8')
        return ast.literal_eval(key_str)

    def verify_message(self, encoded_se_message, original_file_content):
        """[1] Giải mã gói bằng RSA
           [2] Lấy được mã Hash gốc, Chữ ký và PubKey(S)
           [3] Xác thực chữ ký của mã Hash 
           [4] Tự băm lại file gốc nhận được ngoài luồng (original_file_content)
           [5] So sánh hai mã Hash"""
        print("=> Decryption and Detached Signature Verification")
        
        # Giải mã Base64 sang chuỗi list string
        encrypted_se_repr = base64.b64decode(encoded_se_message).decode('utf-8')
        encrypted_se_message_array = json.loads(encrypted_se_repr)
        
        # 1. Giải mã RSA gói dữ liệu để lấy thông tin Pack
        packed_json = self.rsa.decrypt(encrypted_se_message_array, self.pri_key_r)
        print(f"[1] RSA Decryption block completed. Recovered small Packed data.")

        # 2. Xử lý gói (Unpack)
        packed_data = json.loads(packed_json)
        received_hash = packed_data["file_hash"]
        metadata = packed_data["metadata"]
        pub_key_s_raw = packed_data["publickey_sender"]     # List [e, n] từ JSON
        pub_key_s = tuple(pub_key_s_raw)                    # Chuyển lại thành tuple (e, n)
        signature_list = packed_data["signature"]           # List[int] của RSA signature
        
        print(f"[2] Unpack block completed. Detached file reference: '{metadata}'")
        
        # 3. Xác thực chữ ký bằng RSA: Chữ ký này vốn ký lên mã Hash
        is_sig_valid = self.rsa.verify(received_hash, signature_list, pub_key_s)
        if not is_sig_valid:
            print("=> [3] Signature verified FAILED (Signature Mismatch).")
            return False, metadata
            
        print("[3] Signature verified SUCCESSFULLY on the Hash digest.")
        
        # 4. Tự băm lại file gốc nhận được
        from src.hash.SHA256 import SHA256
        sha256 = SHA256()
        msg_bytes = original_file_content.encode('utf-8') if isinstance(original_file_content, str) else original_file_content
        sha256.update(msg_bytes)
        computed_hash = sha256.hexdigest()

        # 5. So sánh mã hash gốc đã được ký và mã hash vừa băm
        if computed_hash == received_hash:
            print("[4] Target file Hash matches the signed Hash. Integrity VERIFIED.")
            return True, metadata
        else:
            print("[4] Target file Hash does NOT match! The file was spoofed or corrupted.")
            return False, metadata

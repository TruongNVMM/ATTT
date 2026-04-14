import os
import sys
import json
import base64
import ast

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from src.asymmetric.DSA.DSA import DSA
from src.asymmetric.RSA.RSA import RSA

class Receiver:
    def __init__(self, private_key_r_path):
        """
        Khởi tạo Class Receiver với khóa
        - PriKey(R): Dùng cho khối Decryption 1 (Giải mã gói S&E Message bằng RSA)
        (Khóa PubKey(S) của Sender sẽ được trích xuất động trong bước Unpack)
        """
        self.dsa = DSA() 
        self.rsa = RSA() 
        
        # Đọc khóa Private Key (RSA) của Receiver
        if os.path.exists(private_key_r_path):
            self.pri_key_r = self._parse_rsa_pem(private_key_r_path)
            """Receiver dùng Private Key (RSA) để giải mã"""
        else:
            raise FileNotFoundError(f"File not found: {private_key_r_path}")

    def _parse_rsa_pem(self, pem_path):
        """Hàm đọc tuple (d, n) của khóa Private RSA từ tệp PEM"""
        with open(pem_path, 'r', encoding='utf-8') as f:
            lines = f.read().strip().split('\n')
        b64_content = "".join([line for line in lines if not line.startswith('-----')])
        key_str = base64.b64decode(b64_content).decode('utf-8')
        return ast.literal_eval(key_str)

    def verify_message(self, encoded_se_message):
        """[1] Giải mã (RSA)  → lấy dữ liệu gốc
           [2] Bóc gói (Unpack) → lấy message + chữ ký + public key sender
           [3] Xác thực chữ ký (DSA)"""
        ''' KHỐI 1: DECRYPTION 
        => GIẢI MÃ BẰNG RSA VỚI PriKey(R) 
        '''
        print("=> Decryption and Signature Verification")
        # Giải mã Base64 sang chuỗi list string
        encrypted_se_repr = base64.b64decode(encoded_se_message).decode('utf-8')
        # Chuyển chuỗi mảng JSON thành Python List (Chứa các số nguyên Ciphertext của RSA)
        encrypted_se_message_array = json.loads(encrypted_se_repr)
        
        # Giải mã RSA để lấy ra JSON string chứa thông tin Pack
        packed_json = self.rsa.decrypt(encrypted_se_message_array, self.pri_key_r)
        print(f"[1] RSA Decryption block completed. Recovered Packed data.")

        ''' KHỐI 2: UNPACK 
        => BÓC TÁCH GÓI 
        '''
        packed_data = json.loads(packed_json)
        plain_message = packed_data["message"]
        pub_key_s = packed_data["publickey_sender"]      # Public key được lấy để xác thực (DSA)
        signature_dict = packed_data["signature"]
        signature = (signature_dict["r"], signature_dict["s"])
        
        print(f"[2] Unpack block completed.")
        print(f"[3] Recovered Message: '{plain_message}'\n")
        
        ''' KHỐI 3 + 4 + 5: VERIFICATION VỚI DSA 
        => Signature Verification 
        => Trong hàm verify() của DSA đã bao gồm cả 3 bước:
            - Hashing (3): Tự băm message thành Digest mới.
            - Decryption (4): Tự tính toán logic so sánh r với v.
            - Are Equal (5): Tự tính toán logic so sánh r với v.
        '''

        msg_bytes = plain_message.encode('utf-8') if isinstance(plain_message, str) else plain_message
        
        is_verified = self.dsa.verify(msg_bytes, signature, pub_key_s)
        
        if is_verified:
            print("=> Signature verified SUCCESSFULLY.")
        else:
            print("=> Signature verified FAILED.")
            
        return is_verified, plain_message


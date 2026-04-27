import os
import sys
import json
import base64
import ast

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from src.asymmetric.RSA.RSA import RSA

class Sender:
    def __init__(self, private_key_s_path, public_key_r_path, public_key_s_path):
        """
        Khởi tạo Class với các khóa cho quá trình gửi (Signature & Encryption)
        - PriKey(S): Phục vụ cho khối Signing 2 (Tạo Signature bằng RSA private key của Sender)
        - PubKey(S): Phục vụ cho khối Pack 3 (Chứa Public Key RSA của Sender để Receiver xác thực)
        - PubKey(R): Phục vụ cho khối Encryption 4 (Mã hóa gói gửi đi bằng RSA public key của Receiver)
        """

        self.rsa_sign = RSA()   # Dùng để ký (sign) với private key của Sender
        self.rsa_enc  = RSA()   # Dùng để mã hóa (encrypt) với public key của Receiver
        
        # Đọc khóa Private Key (RSA) của Sender — dùng ký số
        if os.path.exists(private_key_s_path):
            self.pri_key_s = self._parse_rsa_pem(private_key_s_path)
        else:
            raise FileNotFoundError(f"File not found: {private_key_s_path}")
            
        # Đọc khóa Public Key (RSA) của Sender — đóng gói để Receiver xác thực
        if os.path.exists(public_key_s_path):
            self.pub_key_s = self._parse_rsa_pem(public_key_s_path)
        else:
            raise FileNotFoundError(f"File not found: {public_key_s_path}")

        # Đọc khóa Public Key (RSA) của Receiver — dùng mã hóa gói tin
        if os.path.exists(public_key_r_path):
            self.pub_key_r = self._parse_rsa_pem(public_key_r_path)
        else:
            raise FileNotFoundError(f"File not found: {public_key_r_path}")

    def _parse_rsa_pem(self, pem_path):
        """Hàm phụ trợ đọc nội dung khóa tuple (e/d, n) của RSA từ chuỗi giả PEM Base64"""
        with open(pem_path, 'r', encoding='utf-8') as f:
            lines = f.read().strip().split('\n')
        b64_content = "".join([line for line in lines if not line.startswith('-----')])
        key_str = base64.b64decode(b64_content).decode('utf-8')
        # Dùng literal_eval để an toàn parse chuỗi "(e, n)" hoặc "(d, n)" thành tuple Python
        return ast.literal_eval(key_str)

    def process(self, plain_message):
        print(f"[*] Simulating Heavy File content (e.g., PDF) processing...")
        print("=> Detached Signature and Encryption")
        
        msg_bytes = plain_message.encode('utf-8') if isinstance(plain_message, str) else plain_message

        ''' KHỐI 1: HASHING (Tiêu chuẩn thực tế)
        => Không bế cả file lớn đi ký, mà phải Băm (Hash) file lớn bằng SHA-256
        => Mã hash sinh ra sẽ rất bé (luôn cố định 64 ký tự hex)
        '''
        from src.hash.SHA256 import SHA256
        sha256 = SHA256()
        sha256.update(msg_bytes)
        file_hash = sha256.hexdigest()
        print(f"[1] Hashing completed. Hash digest: {file_hash[:16]}... (size: 64 chars)")
        
        ''' KHỐI 2: SIGNING
        => Cực kỳ nhanh vì chỉ việc Ký số (RSA Sign) lên Mã Hash thay vì hàng mb/gb file gốc.
        '''
        signature_list = self.rsa_sign.sign(file_hash, self.pri_key_s)
        print(f"[2] RSA Signing block completed. Signature generated over Hash.")

        ''' KHỐI 3: DETACHED PACK 
        => Đóng gói THÔNG TIN để gửi (Detached Signature): 
           Chỉ chứa Chữ ký, Khóa công khai, và Mã Hash (hoặc tham chiếu đường dẫn).
           TUYỆT ĐỐI KHÔNG chứa cục plain_message khổng lồ vào đây!
        '''
        packed_data = {
            "metadata": "Attached File or File Path",
            "file_hash": file_hash, 
            "publickey_sender": list(self.pub_key_s),  
            "signature": signature_list                
        }

        packed_json = json.dumps(packed_data)
        print(f"[3] Detached Pack completed. Small payload size: {len(packed_json)} bytes")

        ''' KHỐI 4: ENCRYPTION BẰNG RSA VỚI PubKey(R)
        => Nhờ gói Pack cực kỳ nhỏ gọn, RSA có thể mã hóa dễ dàng. 
        '''
        encrypted_se_message_array = self.rsa_enc.encrypt(packed_json, self.pub_key_r)
        
        encrypted_se_repr = json.dumps(encrypted_se_message_array)
        encoded_se_message = base64.b64encode(encrypted_se_repr.encode('utf-8')).decode('utf-8')
        
        print(f"[4] RSA Encryption block completed. Generated Secure Digital Signature Pack.")

        ''' KHỐI 5: TRANSMISSION '''
        print(f"[5] Ready for Transmission! (The heavy PDF file is sent side-by-side or out-of-band)\n")
        return encoded_se_message

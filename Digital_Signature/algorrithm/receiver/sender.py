import os
import sys
import json
import base64
import ast

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from src.asymmetric.DSA.DSA import DSA
from src.asymmetric.RSA.RSA import RSA

class Sender:
    def __init__(self, private_key_s_path, public_key_r_path, public_key_s_path):
        """
        Khởi tạo Class với các khóa cho quá trình gửi (Signature & Encryption)
        - PriKey(S): Phục vụ cho khối Encryption 2 (Tạo Signature bằng DSA)
        - PubKey(S): Phục vụ cho khối Pack 3 (Chứa Public Key DSA của Sender)
        - PubKey(R): Phục vụ cho khối Encryption 4 (Mã hóa gói gửi đi bằng RSA)
        """

        self.dsa = DSA()
        self.rsa = RSA()
        
        # Đọc khóa Private Key (DSA) của Sender
        if os.path.exists(private_key_s_path):
            self.pri_key_s = self._parse_dsa_pem(private_key_s_path)
        else:
            raise FileNotFoundError(f"File not found: {private_key_s_path}")
            
        # Đọc khóa Public Key (DSA) của Sender để gán vào Pack
        if os.path.exists(public_key_s_path):
            self.pub_key_s = self._parse_dsa_pem(public_key_s_path)
        else:
            raise FileNotFoundError(f"File not found: {public_key_s_path}")

        # Đọc khóa Public Key (RSA) của Receiver
        if os.path.exists(public_key_r_path):
            self.pub_key_r = self._parse_rsa_pem(public_key_r_path)
        else:
            raise FileNotFoundError(f"File not found: {public_key_r_path}")

    def _parse_dsa_pem(self, pem_path):
        """Hàm phụ trợ đọc nội dung khóa integer của DSA từ chuỗi giả PEM Base64"""
        with open(pem_path, 'r', encoding='utf-8') as f:
            lines = f.read().strip().split('\n')
        b64_content = "".join([line for line in lines if not line.startswith('-----')])
        key_str = base64.b64decode(b64_content).decode('utf-8')
        return int(key_str)

    def _parse_rsa_pem(self, pem_path):
        """Hàm phụ trợ đọc nội dung khóa tuple (e, n) của RSA từ chuỗi giả PEM Base64/Str"""
        with open(pem_path, 'r', encoding='utf-8') as f:
            lines = f.read().strip().split('\n')
        b64_content = "".join([line for line in lines if not line.startswith('-----')])
        key_str = base64.b64decode(b64_content).decode('utf-8')

        # Dùng literal_eval để an toàn parse chuỗi "(e, n)" thành tuple Python
        return ast.literal_eval(key_str)

    def process(self, plain_message):
        print(f"[*] Plain Message: '{plain_message}'\n")
        print("=> Signature and Encyption")
        # Chuyển message sang dạng byte
        msg_bytes = plain_message.encode('utf-8') if isinstance(plain_message, str) else plain_message

        ''' KHỐI 1: HASHING 
        => vì trong các thuật toán DSA, RSA, ECDSA đã có hash nên không cần có ở trong đây 
        '''
        
        ''' KHỐI 2: 
        => ENCRYPTION / SIGNING (TẠO CHỮ KÝ SỐ VỚI DSA BẰNG PriKey(S)) 
        '''
        r, s = self.dsa.sign(msg_bytes, self.pri_key_s)
        signature = {"r": r, "s": s}
        print(f"[2] DSA Signing block completed. Signature generated.")


        ''' KHỐI 3: PACK 
        => Đóng gói Message, Signature, và PubKey(S)
        '''
        packed_data = {
            "message": plain_message,
            "publickey_sender": self.pub_key_s,
            "signature": signature
        }

        packed_json = json.dumps(packed_data)
        print(f"[3] Pack block completed. Pack size: {len(packed_json)} bytes")


        ''' KHỐI 4: 
        => ENCRYPTION BẰNG RSA VỚI PubKey(R)
        '''
        encrypted_se_message_array = self.rsa.encrypt(packed_json, self.pub_key_r)
        
        # Chuyển đổi mảng mã hóa thành chuỗi Base64 gọn gàng để truyền qua mạng 
        # (Để dễ dàng xử lý list integers khổng lồ của RSA ciphertext)
        encrypted_se_repr = json.dumps(encrypted_se_message_array)
        encoded_se_message = base64.b64encode(encrypted_se_repr.encode('utf-8')).decode('utf-8')
        
        print(f"[4] RSA Encryption block completed. Generated S&E Message.")


        ''' KHỐI 5: TRANSMISSION 
        => Vận chuyển bản đã mã hóa đi 
        '''
        print(f"[5] Ready for Transmission!\n")
        return encoded_se_message

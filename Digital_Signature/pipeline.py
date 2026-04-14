import os 
import sys
from algorithm.sender.sender import Sender
from algorithm.receiver.receiver import Receiver
import json
import base64

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

# Test trường hợp đúng 
def test_case_1(sender, receiver, message):
    se_message_good = sender.process(message)
    receiver.verify_message(se_message_good)

# Test trường hợp sai (Kẻ thù cố gắng thay đổi nội dung tin nhắn)
def test_case_2(sender, receiver, message_input):
    # Bước 1: Sender ký và mã hoá
    network_message = sender.process(message_input)
    
    # Bước 2: Kẻ tấn công can thiệp vào dữ liệu
    # MÔ PHỎNG: Giả sử attacker đã chặn được gói tin, bằng một cách kì diệu 
    # giải mã được lớp RSA (attacker mượn `receiver.pri_key_r` để giả lập quá trình này)
    # và thay đổi nội dung bên trong bằng cách thêm "WORLD" vào 
    try:
        # Bóc lớp vỏ Base64 nguyên vẹn
        encrypted_se_repr = base64.b64decode(network_message).decode('utf-8')
        encrypted_array = json.loads(encrypted_se_repr)
        
        # Bóc lớp vỏ RSA 
        decrypted_json = receiver.rsa.decrypt(encrypted_array, receiver.pri_key_r)
        data = json.loads(decrypted_json)
        
        data["message"] = data["message"] + " WORLD"
        
        # Bước 3: Người nhận tiến hành xác thực DSA với gói tin đã bị sửa
        msg_bytes = data["message"].encode('utf-8')
        sig = (data["signature"]["r"], data["signature"]["s"])
        pub_s = data["publickey_sender"]
        
        print(f"[3] Recovered Message (Tampered): '{data['message']}'\n")
        
        is_verified = receiver.dsa.verify(msg_bytes, sig, pub_s)
        
        if is_verified:
            print("=> Signature verified SUCCESSFULLY.")
        else:
            print("=> Signature verified FAILED. (Signature Mismatch!) Tampered message detected!")
            
    except Exception as e:
        print(f"System error during extraction: {e}")

def main(): 
    project_root = os.path.dirname(os.path.abspath(__file__))
    
    pri_key_s_path = os.path.join(project_root, 'key', 'sender', 'private_key_sender.pem')
    pub_key_s_path = os.path.join(project_root, 'key', 'sender', 'public_key_sender.pem')
    pub_key_r_path = os.path.join(project_root, 'key', 'receiver', 'public_key_receiver.pem')
    pri_key_r_path = os.path.join(project_root, 'key', 'receiver', 'private_key_receiver.pem')

    if not os.path.exists(pri_key_s_path) or not os.path.exists(pub_key_r_path):
        print("[!] File not found.")
        print("[!] Please create Sender Key using DSA and Receiver Key using RSA.")
        sys.exit(1)

    sender = Sender(
        private_key_s_path=pri_key_s_path,
        public_key_s_path=pub_key_s_path,
        public_key_r_path=pub_key_r_path
    )

    receiver = Receiver(private_key_r_path=pri_key_r_path)

    message = input("Enter message: ")
    index = input("Enter index: ")
    
    if index == "1":
        test_case_1(sender, receiver, message)
    elif index == "2":
        test_case_2(sender, receiver, message)
    else:
        print("[!] Invalid index.")
    

if __name__ == "__main__":
    main()

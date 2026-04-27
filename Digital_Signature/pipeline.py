import os 
import sys
from algorithm.sender.sender import Sender
from algorithm.receiver.receiver import Receiver
import json
import base64

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

# Test trường hợp đúng 
def test_case_1(sender, receiver, message):
    # Sender ký và đóng gói (Detached: Chỉ chứa hash và chữ ký)
    se_message_good = sender.process(message)
    # Receiver nhận được file/message (qua một ngõ tải nhanh, song song) và nhận được gói se_message_good
    receiver.verify_message(se_message_good, message)

# Test trường hợp sai (Kẻ thù cố gắng thay đổi nội dung tin nhắn)
def test_case_2(sender, receiver, message_input):
    # Bước 1: Sender ký và mã hoá gói Detached Signature
    network_packet = sender.process(message_input)
    
    # Bước 2: Kẻ tấn công can thiệp vào dữ liệu
    # MÔ PHỎNG: Kẻ tấn công chặn ngõ tải file và sửa đổi nội dung file lớn (PDF)
    tampered_file = message_input + " WORLD"
    
    print(f"\n[!] Simulation: Attacker intercepted and tampered with the Heavy File content!")
    print(f"[!] Tampered content: '{tampered_file}'\n")

    # Người nhận tiến hành xác thực RSA signature với gói tin gốc và file đã bị sửa
    try:
        receiver.verify_message(network_packet, tampered_file)
    except Exception as e:
        print(f"System error during verification: {e}")

def main(): 
    project_root = os.path.dirname(os.path.abspath(__file__))
    
    pri_key_s_path = os.path.join(project_root, 'key', 'sender', 'private_key_sender.pem')
    pub_key_s_path = os.path.join(project_root, 'key', 'sender', 'public_key_sender.pem')
    pub_key_r_path = os.path.join(project_root, 'key', 'receiver', 'public_key_receiver.pem')
    pri_key_r_path = os.path.join(project_root, 'key', 'receiver', 'private_key_receiver.pem')

    if not os.path.exists(pri_key_s_path) or not os.path.exists(pub_key_r_path):
        print("[!] File not found.")
        print("[!] Please create Sender Key using RSA and Receiver Key using RSA.")
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

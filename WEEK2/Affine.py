import sys
import os

root_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if root_path not in sys.path:
    sys.path.insert(0, root_path)

from Source.CrypytoGraphy_lib import AffineCipher

if __name__ == "__main__":
    A_KEY = 100001
    B_KEY = 12345
    
    try:
        cipher = AffineCipher(A_KEY, B_KEY)
        
        input_text = "Lớp học an toàn thông tin của giảng viên Tạ Thị Kim Huệ! ."
        
        encrypted = cipher.encrypt(input_text)
        decrypted = cipher.decrypt(encrypted)
        
        print(f"--- THÔNG TIN MÃ HÓA ---")
        print(f"Khóa: a = {A_KEY}, b = {B_KEY}")
        print(f"Gốc: {input_text}")
        print(f"Mã : {encrypted}")
        print(f"Giải mã: {decrypted}")
        
        assert input_text == decrypted
        print("\n=> Kết quả: Giải mã thành công 100%, bảo toàn tiếng Việt và khoảng trắng!")

    except ValueError as e:
        print(f"Lỗi: {e}")
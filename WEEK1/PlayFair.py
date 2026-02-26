import sys
import os

root_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if root_path not in sys.path:
    sys.path.insert(0, root_path)

from Source.CrypytoGraphy_lib import PlayfairCipher

if __name__ == "__main__": 
    key = "MONARCHY"
    cipher = PlayfairCipher(key)
    
    plaintext = "INSTRUMENTS"
    
    ciphertext = cipher.process(plaintext, mode='encrypt')
    decrypted = cipher.process(ciphertext, mode='decrypt')
    
    print(f"Khóa (Key): {key}")
    print(f"Văn bản gốc: {plaintext}")
    print(f"Bản mã (Ciphertext): {ciphertext}") 
    print(f"Bản giải mã: {decrypted} (Lưu ý: chữ X ở cuối là padding)")
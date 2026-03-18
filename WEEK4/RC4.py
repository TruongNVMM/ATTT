class RC4: 
    def __init__(self, key):
        self.key = key

    def KSA(self, key): 
        status = list(range(256))
        key = [ord(k) for k in key] # Chuyển khóa thành mã ASCII nếu nó là chuỗi
        j = 0
        for i in range(256): 
            j = (j + status[i] + key[i%len(key)]) % 256 
            status[i], status[j] = status[j], status[i]
        return status
    
    def PRGA(self, status):
        i = 0
        j = 0
        while True: 
            i = (i + 1) % 256 
            j = (j + status[i]) % 256 
            status[i], status[j] = status[j], status[i]
            t = (status[i] + status[j]) % 256
            yield status[t] # Trả về từng byte khóa cho mỗi lần lặp

    def encrypt(self, key, plaintext):
        status = self.KSA(key)
        keystream = self.PRGA(status)
        plaintext = [ord(char) for char in plaintext] # Hàm ord() trả về mã ASCII của ký tự
        ciphertext = ""

        for char in plaintext: 
            k = next(keystream) # Lấy byte khóa tiếp theo từ generator
            ciphertext += chr(char^k) # Hàm chr() chuyển mã ASCII trở lại thành ký tự, và phép XOR để mã hóa

        return ciphertext
    
    def decrypt(self, key, ciphertext):
        # RC4 là một thuật toán stream cipher, nên quá trình giải mã giống hệt như mã hóa
        return self.encrypt(key, ciphertext)


if __name__ == "__main__":
    key = "2501"
    plaintext = "cybersecurity"
    rc4 = RC4(key)
    ciphertext = rc4.encrypt(key, plaintext)
    decrypted_text = rc4.decrypt(key, ciphertext)
    print("Ciphertext:", ciphertext)
    # print("Decrypted Text:", decrypted_text)



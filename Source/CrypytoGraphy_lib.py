import re
import math

class PlayfairCipher:
    def __init__(self, key: str):
        self.matrix = self._generate_matrix(key)

    def _generate_matrix(self, key: str) -> list:
        # Làm sạch từ khóa: viết hoa, thay J bằng I, loại bỏ ký tự không phải chữ
        key = re.sub(r'[^A-Z]', '', key.upper().replace('J', 'I'))
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        
        matrix_str = ""
        # Thêm từ khóa vào chuỗi ma trận (tránh trùng lặp)
        for char in key + alphabet:
            if char not in matrix_str:
                matrix_str += char
                
        # Cắt chuỗi thành mảng 2 chiều 5x5
        return [list(matrix_str[i:i+5]) for i in range(0, 25, 5)]

    def _prepare_text(self, text: str) -> str:
        # Làm sạch văn bản gốc
        text = re.sub(r'[^A-Z]', '', text.upper().replace('J', 'I'))
        prepared = ""
        
        i = 0
        while i < len(text):
            char1 = text[i]
            if i + 1 < len(text):
                char2 = text[i+1]
                if char1 == char2: # Xử lý trùng chữ cái trong cặp
                    prepared += char1 + 'X'
                    i += 1
                else:
                    prepared += char1 + char2
                    i += 2
            else: # Xử lý ký tự bị lẻ ở cuối
                prepared += char1 + 'X'
                i += 1
        return prepared

    def _find_position(self, char: str) -> tuple:
        # Tìm tọa độ (hàng, cột) của một ký tự trong ma trận
        for row in range(5):
            for col in range(5):
                if self.matrix[row][col] == char:
                    return row, col
        raise ValueError(f"Ký tự {char} không tồn tại trong ma trận.")

    def process(self, text: str, mode: str = 'encrypt') -> str:
        if mode == 'encrypt':
            text = self._prepare_text(text)
            shift = 1 # Dịch tiến (phải/xuống)
        elif mode == 'decrypt':
            # Bản mã giả định đã là các cặp hợp lệ
            shift = -1 # Dịch lùi (trái/lên)
        else:
            raise ValueError("Mode chỉ nhận 'encrypt' hoặc 'decrypt'")

        result = ""
        for i in range(0, len(text), 2):
            r1, c1 = self._find_position(text[i])
            r2, c2 = self._find_position(text[i+1])

            # Áp dụng 3 quy tắc
            if r1 == r2: # Cùng hàng
                result += self.matrix[r1][(c1 + shift) % 5] + self.matrix[r2][(c2 + shift) % 5]
            elif c1 == c2: # Cùng cột
                result += self.matrix[(r1 + shift) % 5][c1] + self.matrix[(r2 + shift) % 5][c2]
            else: # Hình chữ nhật (Khác hàng, khác cột)
                result += self.matrix[r1][c2] + self.matrix[r2][c1]

        return result

class AffineCipher:
    def __init__(self, a: int, b: int):
        # M là tổng số ký tự trong chuẩn Unicode
        self.M = 1114112 
        
        # Kiểm tra tính hợp lệ của khóa a
        if math.gcd(a, self.M) != 1:
            # Nếu không nguyên tố cùng nhau, tìm một số a gần nhất hợp lệ để gợi ý
            suggested_a = a
            while math.gcd(suggested_a, self.M) != 1:
                suggested_a += 1
            raise ValueError(f"Khóa a={a} không hợp lệ vì không nguyên tố cùng nhau với {self.M}.\n"
                             f"Gợi ý chọn a = {suggested_a}")
        
        self.a = a
        self.b = b
        # Tính nghịch đảo modulo của a
        self.a_inv = pow(self.a, -1, self.M)

    def encrypt(self, text: str) -> str:
        """Mã hóa chuỗi ký tự Unicode"""
        ciphertext = ""
        for char in text:
            # Lấy mã điểm Unicode của ký tự (bao gồm cả dấu và khoảng trắng)
            # hàm ord() trả về mã điểm Unicode của ký tự và đầu vào chỉ là một ký tự duy nhất
            x = ord(char) 
            # Công thức: E(x) = (ax + b) mod M
            e_x = (self.a * x + self.b) % self.M
            
            # Hàm chr() trả về ký tự Unicode tương ứng với mã điểm đã cho 
            ciphertext += chr(e_x)
        return ciphertext

    def decrypt(self, ciphertext: str) -> str:
        """Giải mã chuỗi ký tự Unicode"""
        plaintext = ""
        for char in ciphertext:
            y = ord(char)
            # Công thức: D(y) = a^-1 * (y - b) mod M
            d_y = (self.a_inv * (y - self.b)) % self.M
            plaintext += chr(d_y)
        return plaintext

class EuclideanGF2:
    """
    Lớp chứa các phương thức liên quan đến phép chia và nhân đa thức trong GF(2)
    """
    
    def poly_divmod(self, a, b):
        """
        Phép chia đa thức lấy nguyên và dư trong GF(2)
        Tham số: 
            - a: số chia
            - b: số bị chia
        Đầu ra: 
            - q: thương
            - r: dư
        Phương thức:
            - Sử dụng bit_length() để xác định bậc của đa thức
        """

        if b == 0:
            raise ZeroDivisionError
        q = 0
        r = a

        # Tiếp tục thực hiện phép chia cho đến khi bậc của r nhỏ hơn bậc của b
        while r >= b and r.bit_length() >= b.bit_length():
            shift = r.bit_length() - b.bit_length()   # Tính số bit cần dịch để b có cùng bậc với r
            q ^= (1 << shift)                         # Phép cộng (XOR) vào thương
            r ^= (b << shift)                         # Phép trừ (XOR) đa thức
        return q, r
    
    def poly_mul(self, a, b):
        """
        Phép nhân đa thức trong GF(2)
        Tham số: 
            - a: đa thức thứ nhất
            - b: đa thức thứ hai
        Đầu ra:
            - res: kết quả của phép nhân
        Phương thức:
            - Sử dụng phép dịch bit và XOR để thực hiện phép nhân
        """

        res = 0
        while b > 0:
            if b & 1:
                res ^= a

            a <<= 1
            b >>= 1
        return res
    
    def extended_gcd_gf2(self, a, b):
        """
        Thuật toán Euclid mở rộng trong GF(2)
        Tham số: 
            - a: đa thức thứ nhất
            - b: đa thức thứ hai
        Đầu ra:
            - gcd: Ước số chung lớn nhất của a và b
            - s: Hệ số s trong phương trình Bézout (s*a + t*b = gcd)
            - t: Hệ số t trong phương trình Bézout (s*a + t*b = gcd)
        Phương thức:
            - Sử dụng phép chia và nhân đa thức trong GF(2)
        """

        old_r, r = a, b
        old_s, s = 1, 0
        old_t, t = 0, 1
        
        while r != 0:
            quotient, remainder = self.poly_divmod(old_r, r)
            
            old_r, r = r, remainder
            old_s, s = s, old_s ^ self.poly_mul(quotient, s)
            old_t, t = t, old_t ^ self.poly_mul(quotient, t)
            
        return old_r, old_s, old_t

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
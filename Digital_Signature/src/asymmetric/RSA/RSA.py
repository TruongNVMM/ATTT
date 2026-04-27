from math import gcd, isqrt
import random

class RSA:
    def __init__(self, bit_length=5):
        """
        Khởi tạo thuật toán RSA. Mặc định dùng bit_length=5 (keysize=32) cho môi trường test nhanh.
        Lưu ý: RSA thực tế cần keysize rất lớn (VD: 2048, 4096), nhưng thuật toán generator 
        của file này có sử dụng cấp phát list `[n for n in range...]` nên nếu keysize = 64 (bit_length=6)
        nó sẽ cố gắng tạo list từ 2 tỷ đến 8 tỷ và treo bộ nhớ.
        """
        self.bit_length = bit_length
        self.keysize = 2 ** bit_length
        self._public_key = None  # (e, n)
        self._private_key = None # (d, n)

    @staticmethod
    def karatsuba(x, y):
        """
        Multiply two non-negative integers using the Karatsuba algorithm.
        """
        if x < 1024 or y < 1024:
            return x * y

        n = max(x.bit_length(), y.bit_length())
        m = n // 2

        # Split: x = x1 * 2^m + x0,  y = y1 * 2^m + y0
        mask = (1 << m) - 1
        x1, x0 = x >> m, x & mask
        y1, y0 = y >> m, y & mask

        z2 = RSA.karatsuba(x1, y1)
        z0 = RSA.karatsuba(x0, y0)
        z1 = RSA.karatsuba(x1 + x0, y1 + y0) - z2 - z0

        return (z2 << (2 * m)) + (z1 << m) + z0

    @staticmethod
    def is_prime(n):
        """Return True if n is a prime number, False otherwise."""
        if n < 2:
            return False
        if n == 2:
            return True
        if n % 2 == 0:
            return False
        for i in range(3, isqrt(n) + 1, 2):
            if n % i == 0:
                return False
        return True

    @staticmethod
    def mod_inverse(a, m):
        """Extended Euclidean Algorithm — returns a^-1 mod m."""
        if gcd(a, m) != 1:
            return -1
        old_r, r     = a, m
        old_s, s     = 1, 0
        while r != 0:
            q         = old_r // r
            old_r, r  = r, old_r - q * r
            old_s, s  = s, old_s - q * s
        return old_s % m

    def generate_keypair(self, keysize=None):
        """
        Generate an RSA public/private key pair.
        Returns ((e, n), (d, n))
        """
        if keysize is None:
            keysize = self.keysize

        nMin = 1 << (keysize - 1)
        nMax = (1 << keysize) - 1

        start = 1 << (keysize // 2 - 1)
        stop  = 1 << (keysize // 2 + 1)

        if start >= stop:
            raise ValueError("Key size too small to generate distinct primes.")

        primes = [n for n in range(start, stop + 1) if RSA.is_prime(n)]

        p = q = 0
        # Tối ưu hóa: Thay vì xây dựng list Cartesian product O(N^2) gây treo máy
        # Chúng ta random chọn 2 số nguyên tố cho đến khi thỏa mãn điều kiện nMin <= p*q <= nMax
        while True:
            candidate_p = random.choice(primes)
            candidate_q = random.choice(primes)
            if candidate_p != candidate_q and nMin <= (candidate_p * candidate_q) <= nMax:
                p = candidate_p
                q = candidate_q
                break

        if p == 0:
            raise ValueError("Could not find suitable prime pair for the given key size.")

        n   = RSA.karatsuba(p, q)
        phi = RSA.karatsuba(p - 1, q - 1)

        while True:
            e = random.randrange(2, phi)
            if gcd(e, phi) == 1:
                d = RSA.mod_inverse(e, phi)
                if d != -1 and e != d:
                    break

        self._public_key = (e, n)
        self._private_key = (d, n)
        return self._public_key, self._private_key

    def set_public_key(self, public_key):
        """Gán Public Key từ bên ngoài (e, n)"""
        self._public_key = public_key

    def set_private_key(self, private_key):
        """Gán Private Key từ bên ngoài (d, n)"""
        self._private_key = private_key

    def encrypt(self, plaintext, public_key=None):
        """Encrypt a plaintext string using the public key."""
        pub_key = public_key if public_key is not None else self._public_key
        if pub_key is None:
            raise RuntimeError("No public key loaded for encryption.")
        
        e, n = pub_key
        return [pow(ord(c), e, n) for c in plaintext]

    def decrypt(self, ciphertext, private_key=None):
        """Decrypt a list of ciphertext integers using the private key."""
        priv_key = private_key if private_key is not None else self._private_key
        if priv_key is None:
            raise RuntimeError("No private key loaded for decryption.")
            
        d, n = priv_key
        return ''.join(chr(pow(c, d, n)) for c in ciphertext)

    def sign(self, message, private_key=None):
        """
        Ký số một thông điệp bằng private key.
        Ở đây ta ký trực tiếp từng ký tự (Mục đích minh họa học tập).

        Args:
            message (str): Thông điệp cần ký.
            private_key (tuple, optional): (d, n) — nếu None sẽ dùng self._private_key.
        Returns:
            List[int]: Chữ ký số dưới dạng danh sách số nguyên.
        """
        priv_key = private_key if private_key is not None else self._private_key
        if priv_key is None:
            raise RuntimeError("No private key loaded to sign.")
        
        d, n = priv_key
        # Trong thực tế phải Hash message rồi ký lên mã Hash đó
        return [pow(ord(c), d, n) for c in message]

    def verify(self, message, signature, public_key=None):
        """
        Xác minh chữ ký.
        """
        pub_key = public_key if public_key is not None else self._public_key
        if pub_key is None:
            raise RuntimeError("No public key loaded for verification.")
            
        e, n = pub_key
        try:
            decrypted_message = ''.join(chr(pow(s, e, n)) for s in signature)
            return message == decrypted_message
        except Exception:
            return False
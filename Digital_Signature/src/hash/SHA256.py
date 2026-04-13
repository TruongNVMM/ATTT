def to_32_bit (n):
    return n & 0xFFFFFFFF
def rotate_right (n, d):
    return to_32_bit((n >> d) | (n << (32 - d)))
def choose (x, y, z):
    return (x & y) ^ (~x & z)
def majority (x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)
def uppercase_sigma0 (x):
    return rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22)
def uppercase_sigma1 (x):
    return rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25)
def lowercase_sigma0 (x):
    return rotate_right(x, 7) ^ rotate_right(x, 18) ^ (x >> 3)
def lowercase_sigma1 (x):
    return rotate_right(x, 17) ^ rotate_right(x, 19) ^ (x >> 10)
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]
# Giá trị băm khởi tạo ban đầu
H_INIT = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

def sha256(message):
    # Chuyển string sang bytearray để xử lý
    if isinstance(message, str):
        msg_bytes = bytearray(message, 'utf-8')
    else:
        msg_bytes = bytearray(message)
        
    length_in_bits = len(msg_bytes) * 8
    
    # Padding: Thêm bit 1 (0x80) vào cuối
    msg_bytes.append(0x80)
    
    # Nhồi thêm byte 0 cho đến khi chia 64 dư 56
    while (len(msg_bytes) % 64) != 56:
        msg_bytes.append(0x00)
        
    # Gắn chiều dài bit (8 bytes) vào cuối cùng
    msg_bytes += length_in_bits.to_bytes(8, byteorder='big')
    
    H = H_INIT.copy()
    
    # Xử lý từng block 64 byte
    for i in range(0, len(msg_bytes), 64):
        chunk = msg_bytes[i : i+64]
        W = [0] * 64
        
        for j in range(16):
            W[j] = int.from_bytes(chunk[j*4 : j*4+4], 'big')
            
        for j in range(16, 64):
            W[j] = to_32_bit(lowercase_sigma1(W[j-2]) + W[j-7] + lowercase_sigma0(W[j-15]) + W[j-16])
            
        a, b, c, d, e, f, g, h = H
        
        # 64 vòng lặp nén
        for j in range(64):
            temp1 = to_32_bit(h + uppercase_sigma1(e) + choose(e, f, g) + K[j] + W[j])
            temp2 = to_32_bit(uppercase_sigma0(a) + majority(a, b, c))
            
            h = g
            g = f
            f = e
            e = to_32_bit(d + temp1)
            d = c
            c = b
            b = a
            a = to_32_bit(temp1 + temp2)
            
        H[0] = to_32_bit(H[0] + a)
        H[1] = to_32_bit(H[1] + b)
        H[2] = to_32_bit(H[2] + c)
        H[3] = to_32_bit(H[3] + d)
        H[4] = to_32_bit(H[4] + e)
        H[5] = to_32_bit(H[5] + f)
        H[6] = to_32_bit(H[6] + g)
        H[7] = to_32_bit(H[7] + h)
        
    # Nối 8 mảng 32-bit lại thành chuỗi hex dài 64 ký tự
    return ''.join(f'{value:08x}' for value in H)

# Test thử kết quả
if __name__ == "__main__":
    text = "hello world"
    print(sha256(text))
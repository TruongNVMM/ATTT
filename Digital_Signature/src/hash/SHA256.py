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
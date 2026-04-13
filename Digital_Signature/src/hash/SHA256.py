def to_32_bit (n):
    return n & 0xFFFFFFFF
def rotate_right (n, d):
    return to_32_bit((n >> d) | (n << (32 - d)))
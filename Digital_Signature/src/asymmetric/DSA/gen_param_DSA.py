import os
import math

def random_in_range(lo, hi):
    span = hi - lo + 1
    byte_len = (span.bit_length() + 7) // 8
    mask = (1 << span.bit_length()) - 1
    while True:
        candidate = int.from_bytes(os.urandom(byte_len), 'big') & mask
        if candidate < span:
            return lo + candidate

def random_bits(n):
    return int.from_bytes(os.urandom((n + 7) // 8), 'big') >> (8 - n % 8 if n % 8 else 0)

def miller_rabin(n, rounds=40):
    if n < 2: return False
    if n == 2: return True
    if n % 2 == 0: return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = random_in_range(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    while True:
        n = random_bits(bits)
        n |= (1 << (bits - 1)) | 1
        if miller_rabin(n, rounds=40):
            return n

print("Generating q (160-bit prime)...")
q = generate_prime(160)
print(f"q = 0x{q:X}")
print(f"q bits = {q.bit_length()}")

print("Generating p (1024-bit prime, p = k*q + 1)...")
L = 1024
N = 160
attempt = 0
while True:
    attempt += 1
    k = random_bits(L - N)
    k |= 1  # make k even so k*q+1 is even? No, we need p odd. q is odd, k*q is odd*k. if k is even, k*q is even, k*q+1 is odd. Good.
    if k % 2 == 1:
        k += 1  # make k even so p = k*q + 1 is odd (since q is odd, even*odd=even, even+1=odd)
    p = k * q + 1
    if p.bit_length() == L and miller_rabin(p, rounds=40):
        break
    if attempt % 1000 == 0:
        print(f"  ... attempt {attempt}")

print(f"p = 0x{p:X}")
print(f"p bits = {p.bit_length()}")

print("Finding generator g...")
h = 2
exp = (p - 1) // q
while True:
    g = pow(h, exp, p)
    if g != 1:
        break
    h += 1

print(f"g = 0x{g:X}")

# Verify
print("\n=== Verification ===")
print(f"q divides (p-1)? {(p - 1) % q == 0}")
print(f"g^q mod p == 1?  {pow(g, q, p) == 1}")
print(f"p is prime?      {miller_rabin(p, 40)}")
print(f"q is prime?      {miller_rabin(q, 40)}")
print(f"g != 1?          {g != 1}")
import os
import math
from src.hash.SHA256 import SHA256

class DSA:
    # ── Valid DSA domain parameters (p, q, g) — L=1024, N=160 ───────────────
    # These satisfy the required mathematical properties:
    #   • p and q are prime
    #   • q divides (p - 1)
    #   • g has order q in Z*_p  (i.e. g^q ≡ 1 mod p)
    # In production you would generate your own p, q, g via generate_params().
    
    _DEFAULT_P = int(
        "B2BBC42DA6416CB4896C8FACB0BE51B3C366A87677FAC66AD5235088AEBBBBC8"
        "7F8A15E969E5F74441243AA3699A563B25A472BE0617F84985FF8EFBC382600B"
        "127D48683609AE5FB9BFD66ABBB7C4487A4958818A89328B8B9AEFB79C91598A"
        "53F143A8DD21AA8C7683DC872A03B160D65ABDCF561840C317480FEA6EA0F46F",
        16
    )
    _DEFAULT_Q = int(
        "C130D3C96A6CC9BAD7C663DD2666200C6CAE1175",
        16
    )
    _DEFAULT_G = int(
        "3F0194A549BB57EBF416E29CBF371A4E970DA18210D021D43D54D19977F986BF"
        "9AE8D214100D266C0A05C15608ACA5D191F14DBB146D11A80E2C895E9D9D6D96"
        "CB3AAA973D6D34DCBAEC5BB2C79D1ACBD31E1780FFD5A1236C808B6B31DDF626"
        "BA3BB301A8E5832FD690F9A44FC7BFE8896F83576DC34D2D68329C47D6C09CEE",
        16
    )

    def __init__(self, p=None, q=None, g=None):
        """
        Initialise DSA with domain parameters (p, q, g).
        If omitted, falls back to the built-in 2048/256 defaults.
        """
        self.p = p or self._DEFAULT_P
        self.q = q or self._DEFAULT_Q
        self.g = g or self._DEFAULT_G
        self._private_key = None   # x  — secret scalar in [1, q-1]
        self._public_key  = None   # y  — public point  g^x mod p

    # ── Key generation ────────────────────────────────────────────────────────

    def generate_keypair(self):
        """
        Generate a fresh (private, public) keypair.
        Returns (x, y) where x is the private key integer and y is public.
        """
        x = self._random_in_range(1, self.q - 1)
        y = pow(self.g, x, self.p)          # y = g^x mod p
        self._private_key = x
        self._public_key  = y
        return x, y

    def set_private_key(self, x):
        """Load an existing private key and derive the public key from it."""
        if not (1 <= x <= self.q - 1):
            raise ValueError("Private key x must be in [1, q-1].")
        self._private_key = x
        self._public_key  = pow(self.g, x, self.p)

    def set_public_key(self, y):
        """Load a third-party public key for verification (no private key)."""
        self._public_key = y

    # ── Signing ───────────────────────────────────────────────────────────────

    def sign(self, message, private_key=None):
        """
        Sign *message* (str | bytes | bytearray) with the stored private key.
        Returns the signature as a pair (r, s) of integers.

        Algorithm (FIPS 186-4 §4.6):
          1. Hash the message: z = leftmost N bits of SHA-256(message)
          2. Choose a secret per-message nonce k in [1, q-1]
          3. r = (g^k mod p) mod q          — commitment
          4. s = k^-1 * (z + x*r) mod q    — response
          Retry with a fresh k when r == 0 or s == 0 (negligibly rare).
        """
        priv_key = private_key if private_key is not None else self._private_key
        if priv_key is None:
            raise RuntimeError("No private key loaded. Call generate_keypair() or set_private_key(), or pass private_key directly.")

        z = self._hash_to_int(message)

        while True:
            k   = self._random_in_range(1, self.q - 1)
            r   = pow(self.g, k, self.p) % self.q
            if r == 0:
                continue

            k_inv = self._mod_inverse(k, self.q)
            s     = (k_inv * (z + priv_key * r)) % self.q
            if s == 0:
                continue

            return r, s

    # ── Verification ──────────────────────────────────────────────────────────

    def verify(self, message, signature, public_key=None):
        """
        Verify a (r, s) signature against *message*.
        Uses self._public_key unless an explicit *public_key* integer is given.
        Returns True if valid, False otherwise.

        Algorithm (FIPS 186-4 §4.7):
          1. Reject if r or s lie outside (0, q)
          2. Hash: z = leftmost N bits of SHA-256(message)
          3. w  = s^-1 mod q
          4. u1 = z * w mod q
          5. u2 = r * w mod q
          6. v  = (g^u1 * y^u2 mod p) mod q
          7. Signature is valid iff v == r
        """
        y = public_key if public_key is not None else self._public_key
        if y is None:
            raise RuntimeError("No public key available for verification.")

        r, s = signature

        # Step 1 — boundary check
        if not (0 < r < self.q and 0 < s < self.q):
            return False

        z    = self._hash_to_int(message)
        w    = self._mod_inverse(s, self.q)
        u1   = (z * w) % self.q
        u2   = (r * w) % self.q

        # Compute v using simultaneous square-and-multiply for both bases
        v    = (pow(self.g, u1, self.p) * pow(y, u2, self.p)) % self.p % self.q

        return v == r

    # ── Domain parameter generation (informational) ───────────────────────────

    @staticmethod
    def generate_params(L=2048, N=256):
        """
        Generate fresh DSA domain parameters (p, q, g) from scratch.
        L = bit-length of p, N = bit-length of q (must divide p-1).
        Note: for real deployments use a vetted library; this is illustrative.
        """
        q = DSA._generate_prime(N)
        # Find p such that p = k*q + 1 is also prime
        while True:
            k = DSA._random_bits(L - N)
            p = k * q + 1
            if p.bit_length() == L and DSA._miller_rabin(p):
                break
        # Choose a generator g of the unique order-q subgroup of Z*_p
        h = 2
        exp = (p - 1) // q
        while True:
            g = pow(h, exp, p)
            if g != 1:
                break
            h += 1
        return p, q, g

    # ── Private helpers ───────────────────────────────────────────────────────

    def _hash_to_int(self, message):
        """
        SHA-256 the message and return the leftmost min(N, 256) bits as an int.
        Using the caller-supplied SHA256 class keeps the dependency minimal.
        """
        h = SHA256()
        h.update(message)
        digest_int = int.from_bytes(h.digest(), 'big')
        # Truncate to N bits if needed (here N=256 == digest length, so no-op)
        n = self.q.bit_length()
        shift = max(0, 256 - n)
        return digest_int >> shift

    @staticmethod
    def _mod_inverse(a, m):
        """Extended Euclidean Algorithm — returns a^-1 mod m."""
        if math.gcd(a, m) != 1:
            raise ValueError(f"{a} has no inverse mod {m}.")
        old_r, r     = a, m
        old_s, s     = 1, 0
        while r != 0:
            q         = old_r // r
            old_r, r  = r, old_r - q * r
            old_s, s  = s, old_s - q * s
        return old_s % m

    @staticmethod
    def _random_in_range(lo, hi):
        """Return a cryptographically random integer in [lo, hi]."""
        span      = hi - lo + 1
        byte_len  = (span.bit_length() + 7) // 8
        mask      = (1 << span.bit_length()) - 1
        while True:
            candidate = int.from_bytes(os.urandom(byte_len), 'big') & mask
            if candidate < span:
                return lo + candidate

    @staticmethod
    def _random_bits(n):
        """Return a random n-bit integer."""
        return int.from_bytes(os.urandom((n + 7) // 8), 'big') >> (8 - n % 8 if n % 8 else 0)

    @staticmethod
    def _generate_prime(bits):
        """Generate a random prime of exactly *bits* bits (Miller-Rabin, 64 rounds)."""
        while True:
            n = DSA._random_bits(bits)
            n |= (1 << (bits - 1)) | 1        # force top bit and odd
            if DSA._miller_rabin(n, rounds=64):
                return n

    @staticmethod
    def _miller_rabin(n, rounds=20):
        """Probabilistic primality test — false-positive prob < 4^-rounds."""
        if n < 2:   return False
        if n == 2:  return True
        if n % 2 == 0: return False
        d, r = n - 1, 0
        while d % 2 == 0:
            d //= 2
            r  += 1
        for _ in range(rounds):
            a    = DSA._random_in_range(2, n - 2)
            x    = pow(a, d, n)
            if x in (1, n - 1):
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
class SHA256:
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    def __init__(self):
        self._h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]

    def update(self, message):
        if isinstance(message, str):
            message = bytearray(message, 'ascii')
        elif isinstance(message, bytes):
            message = bytearray(message)
        elif not isinstance(message, bytearray):
            raise TypeError("Input must be str, bytes, or bytearray")

        # Padding
        length = len(message) * 8
        message.append(0x80)
        while (len(message) * 8 + 64) % 512 != 0:
            message.append(0x00)
        message += length.to_bytes(8, 'big')

        # Process blocks
        for i in range(0, len(message), 64):
            self._process_block(message[i:i+64])

    def _process_block(self, block):
        w = []

        # Prepare message schedule
        for t in range(64):
            if t < 16:
                w.append(int.from_bytes(block[t*4:(t+1)*4], 'big'))
            else:
                val = (self._sigma1(w[t-2]) + w[t-7] +
                       self._sigma0(w[t-15]) + w[t-16]) % 2**32
                w.append(val)

        a, b, c, d, e, f, g, h = self._h

        # Main loop
        for t in range(64):
            t1 = (h + self._capsigma1(e) + self._ch(e, f, g) +
                  self.K[t] + w[t]) % 2**32
            t2 = (self._capsigma0(a) + self._maj(a, b, c)) % 2**32

            h = g
            g = f
            f = e
            e = (d + t1) % 2**32
            d = c
            c = b
            b = a
            a = (t1 + t2) % 2**32

        self._h = [
            (self._h[0] + a) % 2**32,
            (self._h[1] + b) % 2**32,
            (self._h[2] + c) % 2**32,
            (self._h[3] + d) % 2**32,
            (self._h[4] + e) % 2**32,
            (self._h[5] + f) % 2**32,
            (self._h[6] + g) % 2**32,
            (self._h[7] + h) % 2**32,
        ]

    def digest(self):
        return b''.join(h.to_bytes(4, 'big') for h in self._h)

    def hexdigest(self):
        return ''.join(f'{h:08x}' for h in self._h)

    # ===== Helper functions =====
    def _rotate_right(self, x, n):
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    def _sigma0(self, x):
        return self._rotate_right(x, 7) ^ self._rotate_right(x, 18) ^ (x >> 3)

    def _sigma1(self, x):
        return self._rotate_right(x, 17) ^ self._rotate_right(x, 19) ^ (x >> 10)

    def _capsigma0(self, x):
        return self._rotate_right(x, 2) ^ self._rotate_right(x, 13) ^ self._rotate_right(x, 22)

    def _capsigma1(self, x):
        return self._rotate_right(x, 6) ^ self._rotate_right(x, 11) ^ self._rotate_right(x, 25)

    def _ch(self, x, y, z):
        return (x & y) ^ (~x & z)

    def _maj(self, x, y, z):
        return (x & y) ^ (x & z) ^ (y & z)


'''
sha = SHA256()
sha.update("hello world")
print(sha.hexdigest())
'''
class RC5:
    _const = {
        16: (0xB7E1, 0x9E37),
        32: (0xB7E15163, 0x9E3779B9),
        64: (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15),
    }

    def __init__(self, w, r, key):
        self.w = w
        self.r = r
        self.key = key

        self.u = w // 8    # word length in bytes
        self.b = len(key)

        self._key_align()
        self._key_extend()
        self._mix()

    def _modular_add(self, a, b):
        return (a + b) % pow(2, self.w)

    def _modular_sub(self,a, b):
        return (a - b) % pow(2, self.w)

    def _left_rotate(self, x, n):
        n %= self.w
        return ((x << n) | (x >> (self.w - n))) & ((1 << self.w) - 1)

    def _right_rotate(self, x, n):
        n %= self.w
        return (x >> n) | ((x & ((1 << n) - 1)) << (self.w - n))

    def _key_align(self):
        while self.b % self.u:
            self.key += b"\x00"
            self.b = len(self.key)

        self.L = []
        for i in range(0, self.b, self.u):
            self.L.append(
                int.from_bytes(self.key[i: (i + self.u)], "little")
            )

    def _key_extend(self):
        P, Q = self._const[self.w]
        self.S = [P]
        for i in range(1, 2*self.r + 2):
            self.S.append(self._modular_add(self.S[i - 1], Q))

    def _mix(self):
        i = j = A = B = 0
        t = max(len(self.L), 2*self.r + 2)

        for s in range(3 * t):
            A = self.S[i] = \
                self._left_rotate(self.S[i] + A + B, 3) % pow(2, self.w)
            B = self.L[j] = \
                self._left_rotate(self.L[j] + A + B, A + B) % pow(2, self.w)

            i = (i + 1) % (2*self.r + 2)
            j = (j + 1) % len(self.L)

    def encrypt_message(self, message):
        A = message >> self.w
        B = message & (pow(2, self.w) - 1)

        A = self._modular_add(A, self.S[0])
        B = self._modular_add(B, self.S[1])

        for i in range(1, self.r + 1):
            A = self._modular_add(self._left_rotate(A ^ B, B), self.S[2*i])
            B = self._modular_add(self._left_rotate(B ^ A, A), self.S[2*i+1])

        return (A << self.w) | B

    def decrypt_message(self, message):
        A = message >> self.w
        B = message & (pow(2, self.w) - 1)

        for i in range(self.r, 0, -1):
            B = self._right_rotate(self._modular_sub(B, self.S[2*i+1]), A) ^ A
            A = self._right_rotate(self._modular_sub(A, self.S[2*i]), B) ^ B

        A = (A - self.S[0]) % pow(2, self.w)
        B = (B - self.S[1]) % pow(2, self.w)

        return (A << self.w) | B

    def encrypt_file(self, iv, in_fp, out_fp):
        with open(in_fp, "rb") as inf, open(out_fp, "wb") as outf:
            while True:
                chunk = inf.read(self.u*2)

                if not chunk:
                    break

                if len(chunk) != self.u*2:
                    chunk = chunk.ljust(self.u*2, b"\x00")

                data = self.encrypt_message(int.from_bytes(chunk, "big") ^ iv)
                iv = data
                outf.write(data.to_bytes(self.u*2, "little"))

    def decrypt_file(self, in_fp, out_fp):
        with open(in_fp, "rb") as inf, open(out_fp, "wb") as outf:
            iv = 0
            while True:
                chunk = int.from_bytes(inf.read(self.u*2), "little")

                if not chunk:
                    break

                data = self.decrypt_message(chunk) ^ iv
                outf.write(data.to_bytes(self.u*2, "big").strip(b'\x00'))
                iv = chunk


if __name__ == "__main__":
    n = RC5(32, 12, b"fdsdsfsd")
    n.encrypt_file(146, "fin", "fout")

    k = RC5(32, 12, b"fdsdsfsd")
    k.decrypt_file("fout", "tem")

    with open("tem", "rb") as f:
        for i in f:
            print(i)

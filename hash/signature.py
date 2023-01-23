from bitstring import BitArray
from random import SystemRandom
from hash import Gost34_11

class Gost3410_94_Signer:
    def __init__(self, private_key, public_key, p, q, a):
        self.private_key = private_key
        self.public_key = public_key
        self.p = p
        self.q = q
        self.a = a
        self.random = SystemRandom()


    def calculate_signature(self, message):
        message_hash = Gost34_11().calculate_hash(message)
        m_rev = message_hash[::-1]
        m = BitArray(m_rev).int
        self.create_random_integer(self.q.bit_length(), self.random)
        fl1 = True
        r = s = k = None
        while fl1 or r == 0 or s == 0:
            fl1 = False
            fl2 = True
            while fl2 or k <= 0 or k >= self.q:
                fl2 = False
                k = self.create_random_integer(self.q.bit_length(), self.random)
            r = (self.a ** k % self.p) % self.q
            s = (k * m  + self.private_key * r) % self.q
        return r, s

    def verify_signature(self, message, r, s):
        message_hash = Gost34_11().calculate_hash(message)
        m_rev = message_hash[::-1]
        m = BitArray(m_rev).int
        zero = 0
        if zero >= r or self.q <= r:
            return False
        if zero >= s or self.q <= s:
            return False
        v = (m ** (self.q - 2)) % self.q
        z1 = s * v % self.q
        z2 = (self.q - r) * v % self.q
        z1 = self.a ** z1 % self.p
        z2 = self.public_key ** z2 % self.p
        u = z1 * z2 % self.p % self.q
        return u == r


    def create_random_integer(self, bit_len, random):
        n_bytes = (bit_len + 7) // 8
        t = random.randbytes(n_bytes)
        x_bits = 8 * n_bytes - bit_len
        t = BitArray(t).int & (255 >> x_bits)
        return t

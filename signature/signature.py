from bitstring import BitArray
from random import SystemRandom

class Gost3410_94_Signer:
    def __init__(self, private_key, public_key, p, q, a):
        self.private_key = private_key
        self.public_key = public_key
        self.p = p
        self.q = q
        self.a = a
        self.random = SystemRandom()


    def calculate_signature(self, message):
        pass
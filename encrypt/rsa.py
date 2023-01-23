from typing import ByteString

from bitstring import BitArray

from encryptor import Encryptor
from utils import split_in_chunks


class RsaEncryptor(Encryptor):
    def __init__(self, n, e, d):
        self.n = n
        self.e = e
        self.d = d
        self.encrypted_part_len = (n.bit_length() + 7) // 8
        self.unencrypted_part_len = self.encrypted_part_len - 1
        if self.unencrypted_part_len <= 0:
            raise Exception("n must be > 255")


    def encrypt(self, data: ByteString):
        data = list(split_in_chunks(data, self.unencrypted_part_len))
        for i, bytes in enumerate(data):
            m = BitArray(bytes=bytes).uint
            c = m ** self.e % self.n
            c_bytes = c.to_bytes(self.encrypted_part_len, 'big')
            data[i] = self.pad_to_size(BitArray(c_bytes), self.encrypted_part_len)
        ret = data[0]
        for elem in data[1:]:
            ret.append(elem)
        return ret.bytes

    def pad_to_size(self, bytes, size):
        length = len(bytes.bytes)
        return bytes if length == size else BitArray(bytearray([0] * (length - size))) + bytes


    def decrypt(self, data: ByteString):
        data = list(split_in_chunks(data, self.encrypted_part_len))
        for i, bytes in enumerate(data):
            c = BitArray(bytes=bytes).uint
            m = c ** self.d % self.n
            m_bytes = m.to_bytes(self.unencrypted_part_len, 'big')
            data[i] = self.pad_to_size(BitArray(m_bytes), self.unencrypted_part_len)
        ret = data[0]
        for elem in data[1:]:
            ret.append(elem)
        v = 3
        return ret.bytes

    def __str__(self):
        return "RSA encryptor"





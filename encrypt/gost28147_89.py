from typing import ByteString

from bitstring import BitArray

from encryptor import Encryptor
from utils import split_in_chunks


class Gost28147_89Encryptor(Encryptor):
    s1 = bytearray([
        0x9, 0x6, 0x3, 0x2, 0x8, 0xB, 0x1, 0x7, 0xA, 0x4, 0xE, 0xF, 0xC, 0x0, 0xD, 0x5
    ])

    s2 = bytearray([
        0x3, 0x7, 0xE, 0x9, 0x8, 0xA, 0xF, 0x0, 0x5, 0x2, 0x6, 0xC, 0xB, 0x4, 0xD, 0x1
    ])

    s3 = bytearray([
        0xE, 0x4, 0x6, 0x2, 0xB, 0x3, 0xD, 0x8, 0xC, 0xF, 0x5, 0xA, 0x0, 0x7, 0x1, 0x9
    ])

    s4 = bytearray([
        0xE, 0x7, 0xA, 0xC, 0xD, 0x1, 0x3, 0x9, 0x0, 0x2, 0xB, 0x4, 0xF, 0x8, 0x5, 0x6
    ])

    s5 = bytearray([
        0xB, 0x5, 0x1, 0x9, 0x8, 0xD, 0xF, 0x0, 0xE, 0x4, 0x2, 0x3, 0xC, 0x7, 0xA, 0x6
    ])

    s6 = bytearray([
        0x3, 0xA, 0xD, 0xC, 0x1, 0x2, 0x0, 0xB, 0x7, 0x5, 0x9, 0x4, 0x8, 0xF, 0xE, 0x6
    ])

    s7 = bytearray([
        0x1, 0xD, 0x2, 0x9, 0x7, 0xA, 0x6, 0x0, 0x8, 0xC, 0x4, 0x5, 0xF, 0x3, 0xB, 0xE
    ])

    s8 = bytearray([
        0xB, 0xA, 0xF, 0x5, 0x0, 0xC, 0xE, 0x8, 0x6, 0x2, 0x3, 0x9, 0x1, 0x7, 0xD, 0x4
    ])

    s = [s1, s2, s3, s4, s5, s6, s7, s8]

    def __init__(self, key):
        self.keys = [elem.int for elem in list(split_in_chunks(BitArray(key), 32))]

    def encrypt(self, data: ByteString) -> ByteString:
        data = list(split_in_chunks(data, 8))
        temp = [0] * 8
        if len(data) > 0:
            temp[-1] = 8 - len(data[-1])
        extension_block = bytearray(temp)
        data.append(extension_block)
        for i, bytes in enumerate(data):
            block = BitArray(bytes=bytes)
            if block.len < 64:
                n = (64 - block.len) // 4
                block.append("0x" + "0" * n)
            data[i] = self.process_block(block, self.get_encryption_key)
        ret = data[0]
        for elem in data[1:]:
            ret.append(elem)
        return ret.bytes

    def process_block(self, block, key_provider_function):
        a = block[:32].uint
        b = block[32:].uint
        for i in range(32):
            key = key_provider_function(i)
            feisel_res = self.feisel_function(a, key)
            round_res = b ^ feisel_res
            if i < 31:
                b = a
                a = round_res
            else:
                b = round_res
        res = BitArray('0x' + '0' * 16)
        res.overwrite(BitArray(bytes=a.to_bytes(4, 'big')), 0)
        res.overwrite(BitArray(bytes=b.to_bytes(4, 'big')), 32)
        return res

    def feisel_function(self, block, key):
        value = block + key
        res = 0
        for i in range(8):
            si = (value >> (4 * i)) & 0x0F
            svalue = self.s[i][si]
            res = res | (svalue << (4 * i))

        return res

    def get_encryption_key(self, i):
        return self.keys[i % 8] if i < 24 else self.keys[7 - i % 8]

    def decrypt(self, data: ByteString):
        data = list(split_in_chunks(data, 8))
        for i, bytes in enumerate(data):
            block = BitArray(bytes=bytes)
            if block.len < 64:
                n = (64 - block.len) // 4
                block.append("0x" + "0" * n)
            data[i] = self.process_block(block, self.get_decryption_key)
        ret = data[0]
        for elem in data[1:-1]:
            ret.append(elem)
        num_to_drop = data[-1].int
        return ret.bytes[:-num_to_drop]

    def get_decryption_key(self, i):
        return self.keys[i % 8] if i < 8 else self.keys[7 - i % 8]

    def __str__(self):
        return "Gost28147_89 encryptor"

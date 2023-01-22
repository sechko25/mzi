from typing import ByteString

from bitstring import BitArray

from encryptor import Encryptor
from utils import split_in_chunks, shift_left_cycled


class DesEncryptor(Encryptor):
    initial_permutation = bytearray([
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
    ])

    extension = bytearray([
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1,
    ])

    s1 = bytearray([
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ])

    s2 = bytearray([
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ])

    s3 = bytearray([
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ])

    s4 = bytearray([
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ])

    s5 = bytearray([
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ])

    s6 = bytearray([
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ])

    s7 = bytearray([
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ])

    s8 = bytearray([
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ])

    s = [s1, s2, s3, s4, s5, s6, s7, s8]

    feisel_permutation = bytearray([
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25,
    ])

    key_permutation = bytearray([
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
    ])

    key_shift = bytearray([1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1])

    key_bits = bytearray([
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
    ])

    last_permutation = bytearray([
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
    ])

    def __init__(self, key):
        key_bits = BitArray(bytes=key)
        c0d0 = BitArray('0x00000000000000')
        for i in range(56):
            extended_key_index = self.key_permutation[i]
            key_index = extended_key_index // 8 * 7 + extended_key_index % 8
            bit = key_bits[key_index] if key_index < 56 else False
            c0d0.set(bit, i)

        self.keys = [BitArray('0x000000000000') for _ in range(16)]
        ci1di1 = c0d0

        def get_ci_di(ci1_di1, i):
            ci1 = ci1_di1[:28]
            di1 = ci1_di1[28:]
            shift_count = self.key_shift[i]
            shift_left_cycled(ci1, shift_count)
            shift_left_cycled(di1, shift_count)
            ci1.append(di1)
            return ci1

        for i in range(16):
            ci1di1 = get_ci_di(ci1di1, i)
            f = 6
            for j in range(self.keys[i].len):
                bit = ci1di1[self.key_bits[j]] if self.key_bits[j] < ci1di1.len else False
                self.keys[i].set(bit, j)

    def encrypt(self, data: ByteString):
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
            data[i] = self.encrypt_block(block)
        ret = data[0]
        for elem in data[1:]:
            ret.append(elem)
        return ret.bytes

    def encrypt_block(self, block):
        n = block.len
        transformed_block = BitArray("0x" + "0" * (n // 4))
        for i in range(n):
            transformed_block.set(block[self.initial_permutation[i] - 1], i)
        for i in range(16):
            transformed_block = self.encryption_function(transformed_block, self.keys[i])
        ret = BitArray("0x" + "0" * (transformed_block.len // 4))
        for i in range(ret.len):
            ret.set(transformed_block[self.last_permutation[i] - 1], i)
        return ret

    def encryption_function(self, block, key):
        l = block[:32]
        r = block[32:]
        l ^= self.feisel_function(r, key)
        r.append(l)
        return r

    def feisel_function(self, block, key):
        extended_block = BitArray("0x" + "0" * 12)
        for j in range(48):
            extended_block.set(block[self.extension[j] - 1], j)
        extended_block ^= key
        transformed_block = BitArray("0x" + "0" * 8)
        for bi in range(8):
            a = 2 * extended_block[bi * 6] + extended_block[bi * 6 + 5]
            b = 8 * extended_block[bi * 6 + 1] + 4 * extended_block[bi * 6 + 2] + 2 * extended_block[bi * 6 + 3] + \
                extended_block[bi * 6 + 4]
            s = self.s[bi][a * 16 + b]
            for i in range(4):
                transformed_block.set(s & (1 << (3 - i)) != 0, bi * 4 + i)

        ret = BitArray("0x" + "0" * (transformed_block.len // 4))
        for i in range(ret.len):
            ret.set(transformed_block[self.feisel_permutation[i] - 1], i)
        return ret

    def decrypt(self, data: ByteString):
        data = list(split_in_chunks(data, 8))
        for i, bytes in enumerate(data):
            block = BitArray(bytes=bytes)
            if block.len < 64:
                n = (64 - block.len) // 4
                block.append("0x" + "0" * n)
            data[i] = self.decrypt_block(block)
        ret = data[0]
        for elem in data[1:-1]:
            ret.append(elem)
        num_to_drop = data[-1].int
        return ret.bytes[:-num_to_drop]

    def decrypt_block(self, block):
        n = block.len
        transformed_block = BitArray("0x" + "0" * (n // 4))
        for i in range(n):
            transformed_block.set(block[self.initial_permutation[i] - 1], i)
        for i in range(15, -1, -1):
            transformed_block = self.decryption_function(transformed_block, self.keys[i])
        ret = BitArray("0x" + "0" * (transformed_block.len // 4))
        for i in range(ret.len):
            ret.set(transformed_block[self.last_permutation[i] - 1], i)
        return ret

    def decryption_function(self, block, key):
        l = block[:32]
        r = block[32:]
        r ^= self.feisel_function(l, key)
        r.append(l)
        return r

    def __str__(self):
        return "DES encryptor"

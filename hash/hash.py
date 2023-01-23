from bitstring import BitArray


class Context:
    len = 0
    left = 0
    h = bytearray([0]*32)
    s = bytearray([0]*32)
    remainder = bytearray([0]*32)



class Gost34_11:
    k87 = [0] * 256
    k65 = [0] * 256
    k43 = [0] * 256
    k21 = [0] * 256

    k8 = bytearray([0x1, 0x3, 0xA, 0x9, 0x5, 0xB, 0x4, 0xF, 0x8, 0x6, 0x7, 0xE, 0xD, 0x0, 0x2, 0xC])
    k7 = bytearray([0xD, 0xE, 0x4, 0x1, 0x7, 0x0, 0x5, 0xA, 0x3, 0xC, 0x8, 0xF, 0x6, 0x2, 0x9, 0xB])
    k6 = bytearray([0x7, 0x6, 0x2, 0x4, 0xD, 0x9, 0xF, 0x0, 0xA, 0x1, 0x5, 0xB, 0x8, 0xE, 0xC, 0x3])
    k5 = bytearray([0x7, 0x6, 0x4, 0xB, 0x9, 0xC, 0x2, 0xA, 0x1, 0x8, 0x0, 0xE, 0xF, 0xD, 0x3, 0x5])
    k4 = bytearray([0x4, 0xA, 0x7, 0xC, 0x0, 0xF, 0x2, 0x8, 0xE, 0x1, 0x6, 0x5, 0xD, 0xB, 0x9, 0x3])
    k3 = bytearray([0x7, 0xF, 0xC, 0xE, 0x9, 0x4, 0x1, 0x0, 0x3, 0xB, 0x5, 0x2, 0x6, 0xA, 0x8, 0xD])
    k2 = bytearray([0x5, 0xF, 0x4, 0x0, 0x2, 0xD, 0xB, 0x9, 0x1, 0x7, 0x6, 0x3, 0xC, 0xE, 0xA, 0x8])
    k1 = bytearray([0xA, 0x4, 0x5, 0x6, 0x8, 0x1, 0x3, 0x7, 0xD, 0xC, 0xE, 0x0, 0x9, 0x2, 0xB, 0xF])

    def __init__(self):
        for i in range(256):
            j = i >> 4
            t = i & 15
            self.k87[i] = self.k8[j] << 4 | self.k7[t] << 24
            self.k65[i] = self.k6[j] << 4 | self.k5[t] << 16
            self.k43[i] = self.k4[j] << 4 | self.k3[t] << 8
            self.k21[i] = self.k2[j] << 4 | self.k1[t]


    def calculate_hash(self, data):
        context = Context()
        self.hash_block(context, data, 0, len(data))
        return self.finish_hash(context)
        pass


    def array_copy(self, src, src_pos, dest, dest_pos, length):
        dest[dest_pos:dest_pos] = src[src_pos:src_pos+length]

    def finish_hash(self, context):
        buf = bytearray([0]*32)
        xh = bytearray([0]*32)
        xs = bytearray([0]*32)
        fin_len = context.len
        self.array_copy(context.h, 0, xh, 0, 32)
        self.array_copy(context.s, 0, xs, 0, 32)
        if context.left > 0:
            self.array_copy(context.remainder, 0, buf, 0, context.left)
            self.hash_step(xh, buf, 0)
            self.add_blocks(32, xs, buf, 0)
            fin_len += context.left
            buf = bytearray([0] * 32)

        fin_len = fin_len << 3
        bptr = 0
        while fin_len > 0:
            buf[bptr] = fin_len and 0xFF
            bptr += 1
            fin_len = fin_len >> 8

        self.hash_step(xh, buf, 0)
        self.hash_step(xh, xs, 0)
        return xh


    def hash_block(self, context, block, _pos, length):
        pos = _pos
        last_pos = pos + length
        if context.left > 0:
            add_bytes = 32 - context.left
            if add_bytes > length:
                add_bytes = length
            self.array_copy(block, pos, context.remainder, context.left, add_bytes)
            context.left += add_bytes
            if context.left < 32:
                return
            pos += add_bytes
            self.hash_step(context.h, context.remainder, 0)
            self.add_blocks(32, context.s, context.remainder, 0)
            context.len += 32
            context.left = 0
        while last_pos - pos >= 32:
            self.hash_step(context.h, block, pos)
            self.add_blocks(32, context.s, block, pos)
            context.len += 32
            pos += 32
        if pos != length:
            context.left = last_pos - pos
            self.array_copy(block, pos, context.remainder, 0, context.left)


    def add_blocks(self, n, left, right, right_pos):
        carry = 0
        for i in range(n):
            sum = left[i] + right[right_pos + i] + carry
            left[i] = sum & 0xff
            carry = sum >> 8
        return carry


    def hash_step(self, xh, xm, mstart):
        xu = bytearray([0]*32)
        xw = bytearray([0]*32)
        xv = bytearray([0]*32)
        xs = bytearray([0]*32)
        key = bytearray([0]*32)

        self.xor_blocks(xw, xh, xm, mstart, 32)
        self.swap_bytes(xw, key)
        self.gost_encrypt(key, xh, 0, xs, 0)

        self.circle_xor8(xh, 0, xu)
        self.circle_xor8(xm, mstart, xv)
        self.circle_xor8(xv, 0, xv)
        self.xor_blocks(xw, xu, xv, 0, 32)
        self.swap_bytes(xw, key)
        self.gost_encrypt(key, xh, 8, xs, 8)
        self.circle_xor8(xu, 0, xu)

        xu[31] = xu[31] ^ 0xff
        xu[29] = xu[29] ^ 0xff
        xu[28] = xu[28] ^ 0xff
        xu[24] = xu[24] ^ 0xff
        xu[23] = xu[23] ^ 0xff
        xu[20] = xu[20] ^ 0xff
        xu[18] = xu[18] ^ 0xff
        xu[17] = xu[17] ^ 0xff
        xu[14] = xu[14] ^ 0xff
        xu[12] = xu[12] ^ 0xff
        xu[10] = xu[10] ^ 0xff
        xu[8] = xu[8] ^ 0xff
        xu[7] = xu[7] ^ 0xff
        xu[5] = xu[5] ^ 0xff
        xu[3] = xu[3] ^ 0xff
        xu[1] = xu[1] ^ 0xff

        self.circle_xor8(xv, 0, xv)
        self.circle_xor8(xv, 0, xv)
        self.xor_blocks(xw, xu, xv, 0, 32)
        self.swap_bytes(xw, key)
        self.gost_encrypt(key, xh, 16, xs, 16)

        self.circle_xor8(xu, 0, xu)
        self.circle_xor8(xv, 0, xv)
        self.circle_xor8(xv, 0, xv)
        self.xor_blocks(xw, xu, xv, 0, 32)
        self.swap_bytes(xw, key)
        self.gost_encrypt(key, xh, 24, xs, 24)

        for i in range(12):
            self.transform3(xs)
        self.xor_blocks(xs, xs, xm, mstart, 32)
        self.transform3(xs)
        self.xor_blocks(xs, xs, xh, 0, 32)
        for i in range(61):
            self.transform3(xs)
        self.array_copy(xs, 0, xh, 0, 32)
        pass


    def transform3(self, data):
        acc = (data[0] ^ data[2] ^ data[4] ^ data[6] ^ data[24] ^ data[30]) | ((data[1] ^ data[3] ^ data[5] ^ data[7] ^
                        data[25] ^ data[31]) << 8)
        buf = list(data)
        self.array_copy(buf, 2, data, 0, 30)
        data[30] = acc & 0xff
        data[31] = acc >> 8




    def xor_blocks(self, res, a, b, b_start, len):
        for i in range(len):
            res[i] = a[i] ^ b[b_start + i]


    def swap_bytes(self, w, k):
        for i in range(4):
            for j in range(4):
                k[i + 4*j] = w[8*i + j]

    def circle_xor8(self, w, w_start, k):
        buf = bytearray([0]*8)
        self.array_copy(w, w_start, buf, 0, 8)
        self.array_copy(w, w_start+8, k, 0, 24)
        for i in range(8):
            k[i + 24] = buf[i] ^ k[i]

    def swap_bytes(self, w, k):
        for i in range(4):
            for j in range(8):
                k[i + 4*j] = w[8*i + j]


    def gost_encrypt(self, key, in_block, in_pos, out_block, out_pos):
        k = [0] * 8
        self.gost_set_key(key, k)
        self.gost_crypt(in_block, in_pos, out_block, out_pos, k)

    def gost_set_key(self, xk, k):
        for i in range(8):
            k[i] = xk[i*4] | (xk[i*4 + 1] << 8) | (xk[i*4 + 2] << 16) | (xk[i*4 + 3] << 24)

    def gost_crypt(self, block, block_pos, output, output_pos, k):
        n1 = block[block_pos] | (block[block_pos+1] << 8) | (block[block_pos+2] << 16) | (block[block_pos+3] << 24)
        n2 = block[block_pos+4] | (block[block_pos+5] << 8) | (block[block_pos+6] << 16) | (block[block_pos+7] << 24)

        n1 = n1 ^ self.f(n2, k[1])
        n2 = n2 ^ self.f(n1, k[2])
        n1 = n1 ^ self.f(n2, k[3])
        n2 = n2 ^ self.f(n1, k[4])
        n1 = n1 ^ self.f(n2, k[5])
        n2 = n2 ^ self.f(n1, k[6])
        n1 = n1 ^ self.f(n2, k[7])
        n2 = n2 ^ self.f(n1, k[0])
        n1 = n1 ^ self.f(n2, k[1])
        n2 = n2 ^ self.f(n1, k[2])
        n1 = n1 ^ self.f(n2, k[3])
        n2 = n2 ^ self.f(n1, k[4])
        n1 = n1 ^ self.f(n2, k[5])
        n2 = n2 ^ self.f(n1, k[6])
        n1 = n1 ^ self.f(n2, k[7])
        n2 = n2 ^ self.f(n1, k[0])
        n1 = n1 ^ self.f(n2, k[1])
        n2 = n2 ^ self.f(n1, k[2])
        n1 = n1 ^ self.f(n2, k[3])
        n2 = n2 ^ self.f(n1, k[4])
        n1 = n1 ^ self.f(n2, k[5])
        n2 = n2 ^ self.f(n1, k[6])
        n1 = n1 ^ self.f(n2, k[7])
        n2 = n2 ^ self.f(n1, k[7])
        n1 = n1 ^ self.f(n2, k[6])
        n2 = n2 ^ self.f(n1, k[5])
        n1 = n1 ^ self.f(n2, k[4])
        n2 = n2 ^ self.f(n1, k[3])
        n1 = n1 ^ self.f(n2, k[2])
        n2 = n2 ^ self.f(n1, k[1])
        n1 = n1 ^ self.f(n2, k[0])
        output[output_pos + 0] = (n2 & 0xff) % 256
        output[output_pos + 1] = (n2 >> 8 & 0xff) % 256
        output[output_pos + 2] = (n2 >> 16 & 0xff) % 256
        output[output_pos + 3] = (n2 >> 24) % 256
        output[output_pos + 4] = (n1 & 0xff) % 256
        output[output_pos + 5] = (n1 >> 8 & 0xff) % 256
        output[output_pos + 6] = (n1 >> 16 & 0xff) % 256
        output[output_pos + 7] = (n1 >> 24) % 256

    def f(self, n, x):
        tmp = n + x
        result = self.k87[tmp >> 24 & 255] | self.k65[tmp >> 16 & 255] | self.k43[tmp >> 8 & 255] | self.k21[tmp & 255]
        return result << 11 | result >> (32 - 11)


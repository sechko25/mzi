from des import DesEncryptor
from gost28147_89 import Gost28147_89Encryptor
from rsa import RsaEncryptor
from utils import verify_encryption

DES_KEY = bytearray([255, 0, 128, 0, 1, 129, 233])
GOST_KEY = bytearray([
    255, 0, 128, 0, 1, 129, 233, 17, 23, 14, 222, 43, 255, 11, 1, 0, 72,
    44, 128, 127, 215, 156, 162, 41, 199, 225, 145, 1, 23, 69, 249, 114,
])
RSA_N = 3233
RSA_E = 17
RSA_D = 2753
MESSAGE = "Hello, world!"

if __name__ == '__main__':
    a = bytearray(MESSAGE, 'utf-8')
    verify_encryption(MESSAGE, DesEncryptor(DES_KEY))
    print()
    verify_encryption(MESSAGE, Gost28147_89Encryptor(GOST_KEY))
    print()
    verify_encryption(MESSAGE, RsaEncryptor(RSA_N, RSA_E, RSA_D))

# See PyCharm help at https://www.jetbrains.com/help/pycharm/

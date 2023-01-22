from des import DesEncryptor
from gost28147_89 import Gost28147_89Encryptor
from tests import test_encryption

DES_KEY = bytearray([255, 0, 128, 0, 1, 129, 233])
GOST_KEY = bytearray([
    255, 0, 128, 0, 1, 129, 233, 17, 23, 14, 222, 43, 255, 11, 1, 0, 72,
    44, 128, 127, 215, 156, 162, 41, 199, 225, 145, 1, 23, 69, 249, 114,
])
MESSAGE = "Hello, world!"

if __name__ == '__main__':
    a = bytearray(MESSAGE, 'utf-8')
    test_encryption(MESSAGE, DesEncryptor(DES_KEY))
    print()
    test_encryption(MESSAGE, Gost28147_89Encryptor(GOST_KEY))

# See PyCharm help at https://www.jetbrains.com/help/pycharm/

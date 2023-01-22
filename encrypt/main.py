from des import DesEncryptor
from tests import test_encryption

DES_KEY = bytearray([255, 0, 128, 0, 1, 129, 233])
MESSAGE = "Hello, world!"

if __name__ == '__main__':
    a = bytearray(MESSAGE, 'utf-8')
    test_encryption(MESSAGE, DesEncryptor(DES_KEY))

# See PyCharm help at https://www.jetbrains.com/help/pycharm/

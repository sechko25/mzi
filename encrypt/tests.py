import unittest

from des import DesEncryptor
from gost28147_89 import Gost28147_89Encryptor
from main import DES_KEY, GOST_KEY, RSA_N, RSA_E, RSA_D
from rsa import RsaEncryptor

MESSAGE = "message to encrypt"


class TestDesEncryptor(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestDesEncryptor, self).__init__(*args, **kwargs)
        self.encryptor = DesEncryptor(DES_KEY)

    def test_encrypted_different_from_origin(self):
        encrypted = self.encryptor.encrypt(bytes(MESSAGE, "utf-16"))
        self.assertNotEqual(MESSAGE, encrypted.decode("utf-16"))

    def test_decryption(self):
        encrypted = self.encryptor.encrypt(bytes(MESSAGE, "utf-16"))
        decrypted = self.encryptor.decrypt(encrypted).decode("utf-16")
        self.assertEqual(MESSAGE, decrypted)


class TestGost2814789Encryptor(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestGost2814789Encryptor, self).__init__(*args, **kwargs)
        self.encryptor = Gost28147_89Encryptor(GOST_KEY)

    def test_encrypted_different_from_origin(self):
        encrypted = self.encryptor.encrypt(bytes(MESSAGE, "utf-16"))
        self.assertNotEqual(MESSAGE, encrypted.decode("utf-16"))

    def test_decryption(self):
        encrypted = self.encryptor.encrypt(bytes(MESSAGE, "utf-16"))
        decrypted = self.encryptor.decrypt(encrypted).decode("utf-16")
        self.assertEqual(MESSAGE, decrypted)


class TestRsaEncryptor(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestRsaEncryptor, self).__init__(*args, **kwargs)
        self.encryptor = RsaEncryptor(RSA_N, RSA_E, RSA_D)

    def test_encrypted_different_from_origin(self):
        encrypted = self.encryptor.encrypt(bytes(MESSAGE, 'ISO-8859-1'))
        decrypted = encrypted.decode('ISO-8859-1')
        self.assertNotEqual(MESSAGE, decrypted)

    def test_decryption(self):
        encrypted = self.encryptor.encrypt(bytes(MESSAGE, "utf-16"))
        decrypted = self.encryptor.decrypt(encrypted).decode("utf-16")
        self.assertEqual(MESSAGE, decrypted)


if __name__ == '__main__':
    unittest.main()

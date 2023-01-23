import unittest

from hash import Gost34_11
from signature import Gost3410_94_Signer

MESSAGE = "Hello, world!"


class TestHasher(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestHasher, self).__init__(*args, **kwargs)
        self.hasher = Gost34_11()

    def test_hash_not_empty(self):
        hash = self.hasher.calculate_hash(MESSAGE.encode("utf-16"))
        self.assertTrue(len(hash) != 0)

    def test_hash_differs(self):
        message1 = "one message"
        message2 = "another message"
        hash1 = self.hasher.calculate_hash(message1.encode("utf-16"))
        hash2 = self.hasher.calculate_hash(message2.encode("utf-16"))
        self.assertNotEqual(hash2, hash1)


if __name__ == '__main__':
    unittest.main()

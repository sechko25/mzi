from abc import ABC, abstractmethod
from typing import ByteString


class Encryptor(ABC):
    @abstractmethod
    def encrypt(self, data: ByteString) -> ByteString:
        pass

    @abstractmethod
    def decrypt(self, data: ByteString) -> ByteString:
        pass

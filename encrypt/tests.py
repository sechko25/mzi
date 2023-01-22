from encryptor import Encryptor


def test_encryption(message: str, encryptor: Encryptor):
    print(f"Testing {encryptor}")
    print(f"Message to encrypt: {message}")
    encrypted_bytes = encryptor.encrypt(bytearray(message, 'utf-8'))
    print(f"Encrypted message: {encrypted_bytes.decode('utf-16')}")
    decrypted_bytes = encryptor.decrypt(encrypted_bytes)
    decrypted_message = decrypted_bytes.decode()
    print(f"Decrypted message: {decrypted_message}")
    if decrypted_message == message:
        print(f"{encryptor} succeed")
    else:
        print(f"{encryptor} failed")


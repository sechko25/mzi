from encryptor import Encryptor


def split_in_chunks(list_a, chunk_size):
    for i in range(0, len(list_a), chunk_size):
        yield list_a[i:i + chunk_size]


def shift_left_cycled(b, n):
    cycled_bits = [b[i] for i in range(n)]
    b <<= n
    for i in range(n):
        b.set(cycled_bits[i], len(b) - n + i - 1)


def verify_encryption(message: str, encryptor: Encryptor):
    print(f"Testing {encryptor}")
    print(f"Message to encrypt: {message}")
    encrypted_bytes = encryptor.encrypt(bytearray(message, 'ISO-8859-1'))
    print(f"Encrypted message: {encrypted_bytes.decode('ISO-8859-1')}")
    decrypted_bytes = encryptor.decrypt(encrypted_bytes)
    decrypted_message = decrypted_bytes.decode()
    print(f"Decrypted message: {decrypted_message}")
    if decrypted_message == message:
        print(f"{encryptor} succeed")
    else:
        print(f"{encryptor} failed")

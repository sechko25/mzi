from hash import Gost34_11
from signature import Gost3410_94_Signer

TEXT = "Hello, world!"

if __name__ == '__main__':
    a = Gost34_11().calculate_hash(bytes(TEXT, "utf-8"))
    print(f"Text to be hashed: {TEXT}")
    print("Hash:")
    print(" ".join(hex(elem)[2:].upper() for elem in a))
    print()
    print(f"Text to be signed: {TEXT}")
    signer = Gost3410_94_Signer(3, 9, 11, 5, 4)
    r, s = signer.calculate_signature(bytearray(TEXT, "utf-16"))
    print(f"Signature for the message: r - {r}, s - {s}")
    success = signer.verify_signature(bytearray(TEXT, "utf-16"), r, s)
    if success:
        print("Signature verification succeed")
    else:
        print("Signature verification failed")

# See PyCharm help at https://www.jetbrains.com/help/pycharm/

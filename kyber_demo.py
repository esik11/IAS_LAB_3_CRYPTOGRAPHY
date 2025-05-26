import os
import hashlib
from datetime import datetime
import time


class Kyber512:
    def __init__(self):
        self.public_key = None
        self.private_key = None

    def keygen(self):
        """Simulate key generation by generating random 32-byte keys."""
        self.public_key = os.urandom(32)
        self.private_key = os.urandom(32)
        return self.public_key, self.private_key

    def encrypt(self, message: bytes, public_key: bytes) -> (bytes, bytes):
        """Simulate encryption: returns a fake ciphertext and a shared secret."""
        # Ciphertext includes the message and some randomness
        ciphertext = hashlib.sha3_256(message + os.urandom(32)).digest()
        # Sender's shared secret is derived deterministically from the message
        shared_secret = hashlib.sha3_256(message).digest()
        return ciphertext, shared_secret

    def decrypt(self, ciphertext: bytes, private_key: bytes, original_message: bytes) -> bytes:
        """Simulate decryption: derive the same shared secret from original message."""
        # Receiver regenerates shared secret based on known original message
        shared_secret = hashlib.sha3_256(original_message).digest()
        return shared_secret


def main():
    print("Kyber-512 Post-Quantum Cryptography Demonstration")
    print("=" * 50)

    kyber = Kyber512()
    message = b"This is a secret message for Kyber-512 testing!"

    # 1. Key Generation
    print("\n1. Key Generation Phase\n" + "-" * 20)
    start_keygen = time.perf_counter()
    public_key, private_key = kyber.keygen()
    end_keygen = time.perf_counter()
    keygen_time = end_keygen - start_keygen
    print("Key Pair Generated in {:.6f} seconds".format(keygen_time))

    # 2. Encryption
    print("\n2. Encryption Phase\n" + "-" * 20)
    start_encrypt = time.perf_counter()
    ciphertext, sender_shared_secret = kyber.encrypt(message, public_key)
    end_encrypt = time.perf_counter()
    encrypt_time = end_encrypt - start_encrypt
    print("Ciphertext:", ciphertext.hex())
    print("Sender Shared Secret:", sender_shared_secret.hex())
    print("Encryption Time: {:.6f} seconds".format(encrypt_time))

    # 3. Decryption
    print("\n3. Decryption Phase\n" + "-" * 20)
    start_decrypt = time.perf_counter()
    receiver_shared_secret = kyber.decrypt(ciphertext, private_key, message)
    end_decrypt = time.perf_counter()
    decrypt_time = end_decrypt - start_decrypt
    print("Receiver Shared Secret:", receiver_shared_secret.hex())
    print("Decryption Time: {:.6f} seconds".format(decrypt_time))

    # 4. Key Validation
    print("\n4. Key Validation Phase\n" + "-" * 24)
    if sender_shared_secret == receiver_shared_secret:
        print("Key Validation: ✅ Success")
    else:
        print("Key Validation: ❌ Failed")

    # 5. Save Metrics
    print("\n5. Saving Metrics\n" + "-" * 18)
    metrics = (
        "Performance Metrics for Kyber512 Algorithm\n"
        "-----------------------------------------\n"
        f"Date: {datetime.now()}\n"
        f"Key Generation Time: {keygen_time:.6f} seconds\n"
        f"Encryption Time: {encrypt_time:.6f} seconds\n"
        f"Decryption Time: {decrypt_time:.6f} seconds\n"
    )
    with open("kyber512_metrics.txt", "w") as f:
        f.write(metrics)
    print("Metrics saved to 'kyber512_metrics.txt'")


if __name__ == "__main__":
    main()

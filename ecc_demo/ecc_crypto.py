import os
import subprocess
import base64
from pathlib import Path

class ECCCrypto:
    def __init__(self, base_dir="."):
        self.base_dir = Path(base_dir)
        self.keys_dir = self.base_dir / "keys"
        self.encrypted_dir = self.base_dir / "encrypted"
        self.messages_dir = self.base_dir / "messages"
        
        self.keys_dir.mkdir(exist_ok=True)
        self.encrypted_dir.mkdir(exist_ok=True)
        self.messages_dir.mkdir(exist_ok=True)

    def generate_ecc_key_pair(self, name="user"):
        """Generate ECC key pair using OpenSSL"""
        private_key_path = self.keys_dir / f"{name}_private.pem"
        public_key_path = self.keys_dir / f"{name}_public.pem"
        
        print(f"\n🔐 Generating ECC key pair for {name.title()}...")
        subprocess.run([
            "openssl", "ecparam", "-name", "secp256k1", "-genkey", "-noout",
            "-out", str(private_key_path)
        ], check=True)
        
        subprocess.run([
            "openssl", "ec", "-in", str(private_key_path),
            "-pubout", "-out", str(public_key_path)
        ], check=True)

        print(f"✅ {name.title()}'s ECC key pair generated.")
        return private_key_path, public_key_path

    def encrypt_message(self, message, recipient_public_key_path, sender="jeorge"):
        """Encrypt message using ECIES"""
        message_path = self.messages_dir / f"{sender}_message.txt"
        encrypted_message_path = self.encrypted_dir / f"{sender}_to_andrei_encrypted.bin"
        
        with open(message_path, "w") as f:
            f.write(message)

        ephemeral_private = self.encrypted_dir / "ephemeral_private.pem"
        ephemeral_public = self.encrypted_dir / "ephemeral_public.pem"
        
        print(f"\n🔑 {sender.title()} is generating an ephemeral key pair for message encryption...")
        subprocess.run([
            "openssl", "ecparam", "-name", "secp256k1", "-genkey", "-noout",
            "-out", str(ephemeral_private)
        ], check=True)

        subprocess.run([
            "openssl", "ec", "-in", str(ephemeral_private),
            "-pubout", "-out", str(ephemeral_public)
        ], check=True)

        shared_secret_path = self.encrypted_dir / "shared_secret.bin"
        subprocess.run([
            "openssl", "pkeyutl", "-derive",
            "-inkey", str(ephemeral_private),
            "-peerkey", str(recipient_public_key_path),
            "-out", str(shared_secret_path)
        ], check=True)

        subprocess.run([
            "openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "10000",
            "-in", str(message_path),
            "-out", str(encrypted_message_path),
            "-pass", f"file:{shared_secret_path}"
        ], check=True)

        return encrypted_message_path, ephemeral_public

    def decrypt_message(self, encrypted_message_path, ephemeral_public_path, private_key_path):
        """Decrypt ECIES-encrypted message"""
        print("\n🔓 Decrypting the message using ECDH-derived key...")
        shared_secret_path = self.encrypted_dir / "shared_secret.bin"

        subprocess.run([
            "openssl", "pkeyutl", "-derive",
            "-inkey", str(private_key_path),
            "-peerkey", str(ephemeral_public_path),
            "-out", str(shared_secret_path)
        ], check=True)

        decrypted_message_path = self.messages_dir / "decrypted_by_andrei.txt"

        subprocess.run([
            "openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "10000",
            "-in", str(encrypted_message_path),
            "-out", str(decrypted_message_path),
            "-pass", f"file:{shared_secret_path}"
        ], check=True)

        with open(decrypted_message_path, "r") as f:
            return f.read()

    def perform_ecdh(self, private_path, public_path, initiator):
        """Perform ECDH key exchange and return shared secret"""
        print(f"\n🔐 {initiator.title()} is performing ECDH key exchange...")
        shared_secret_path = self.encrypted_dir / f"{initiator}_shared_secret.bin"
        subprocess.run([
            "openssl", "pkeyutl", "-derive",
            "-inkey", str(private_path),
            "-peerkey", str(public_path),
            "-out", str(shared_secret_path)
        ], check=True)

        with open(shared_secret_path, "rb") as f:
            return f.read()

def main():
    print("📘 Welcome to the ECC Encryption Demo with Jeorge and Andrei!\n")

    crypto = ECCCrypto()

    # Key Generation
    jeorge_private, jeorge_public = crypto.generate_ecc_key_pair("jeorge")
    andrei_private, andrei_public = crypto.generate_ecc_key_pair("andrei")

    # Jeorge writes and encrypts message to Andrei
    message = input("\n💬 Jeorge, enter your secret message to Andrei: ")
    encrypted_message, ephemeral_public = crypto.encrypt_message(message, andrei_public, sender="jeorge")

    print("\n📤 Encrypted message (base64 format):")
    with open(encrypted_message, "rb") as f:
        print(base64.b64encode(f.read()).decode())

    # Andrei decrypts the message
    decrypted = crypto.decrypt_message(encrypted_message, ephemeral_public, andrei_private)
    print(f"\n📥 Andrei decrypted the message:\n\"{decrypted}\"")

    # ECDH Demonstration
    print("\n🔁 Demonstrating ECDH Key Exchange:")
    jeorge_secret = crypto.perform_ecdh(jeorge_private, andrei_public, "jeorge")
    andrei_secret = crypto.perform_ecdh(andrei_private, jeorge_public, "andrei")

    print(f"\n🔑 Jeorge's Shared Secret: {jeorge_secret.hex()}")
    print(f"🔑 Andrei's Shared Secret: {andrei_secret.hex()}")
    print(f"\n✅ Shared secrets match: {jeorge_secret == andrei_secret}")

if __name__ == "__main__":
    main()

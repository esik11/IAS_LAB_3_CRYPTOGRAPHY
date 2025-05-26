# Import the Paillier encryption scheme from the 'phe' library
from phe import paillier

# Import datetime module for timestamping logs
import datetime

# Generate a public and private key pair for encryption and decryption
public_key, private_key = paillier.generate_paillier_keypair()

# Define the log file path
log_file = "paillier_log.txt"

# Function to write encryption operations and results to a log file
def log_to_file(operation, a, b, encrypted_a, encrypted_b, encrypted_result, decrypted_result):
    with open(log_file, "a") as f:
        f.write("===== New Operation =====\n")
        f.write(f"Timestamp: {datetime.datetime.now()}\n")
        f.write(f"Operation: {operation}\n")
        f.write(f"Input A: {a}\n")
        f.write(f"Input B: {b}\n")
        f.write(f"Encrypted A: {encrypted_a.ciphertext() if encrypted_a else 'N/A'}\n")
        f.write(f"Encrypted B: {encrypted_b.ciphertext() if encrypted_b else 'N/A'}\n")
        f.write(f"Encrypted Result: {encrypted_result.ciphertext()}\n")
        f.write(f"Decrypted Result: {decrypted_result}\n")
        f.write("=========================\n\n")

# Encrypt a number using the public key
def encrypt_number(number):
    return public_key.encrypt(number)

# Decrypt a number using the private key
def decrypt_number(encrypted_number):
    return private_key.decrypt(encrypted_number)

# Main user interface loop
def main_menu():
    print("🔐 Paillier Homomorphic Encryption with Logging")
    while True:
        print("\nChoose an operation:")
        print("1. Encrypted Addition (A + B)")
        print("2. Encrypted Multiplication (A × plain B)")
        print("3. Exit")

        choice = input("Enter your choice: ")

        # Homomorphic Addition: encrypted_a + encrypted_b = encryption of (a + b)
        if choice == '1':
            try:
                a = int(input("Enter number A: "))
                b = int(input("Enter number B: "))

                # Encrypt both inputs
                encrypted_a = encrypt_number(a)
                encrypted_b = encrypt_number(b)

                # ✅ Homomorphic operation: computation on encrypted data
                encrypted_result = encrypted_a + encrypted_b
                # Note: no decryption needed before this addition

                # Decrypt the result for verification
                decrypted_result = decrypt_number(encrypted_result)

                # Show result to user
                print(f"Decrypted Result: {a} + {b} = {decrypted_result}")

                # Log all details
                log_to_file("Addition", a, b, encrypted_a, encrypted_b, encrypted_result, decrypted_result)

            except ValueError:
                print("❌ Please enter valid integers.")

        # Homomorphic Scalar Multiplication: encrypted_a * b = encryption of (a * b)
        elif choice == '2':
            try:
                a = int(input("Enter number A (to encrypt): "))
                b = int(input("Enter constant B (plaintext): "))

                # Encrypt the first input
                encrypted_a = encrypt_number(a)

                # ✅ Homomorphic operation: scalar multiplication on encrypted data
                encrypted_result = encrypted_a * b
                # Note: B is not encrypted, but the result is as if a * b was encrypted directly

                # Decrypt the result for verification
                decrypted_result = decrypt_number(encrypted_result)

                # Show result to user
                print(f"Decrypted Result: {a} * {b} = {decrypted_result}")

                # Log operation; encrypted_b is None here since B is plaintext
                log_to_file("Multiplication", a, b, encrypted_a, None, encrypted_result, decrypted_result)

            except ValueError:
                print("❌ Please enter valid integers.")

        # Exit the program
        elif choice == '3':
            print("📁 Log saved in:", log_file)
            print("👋 Exiting.")
            break

        else:
            print("❗ Invalid choice. Choose 1, 2, or 3.")

# Run the menu function to start the program
main_menu()

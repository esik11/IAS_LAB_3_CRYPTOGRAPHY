# Elliptic Curve Cryptography (ECC) Implementation

This implementation demonstrates various aspects of Elliptic Curve Cryptography using OpenSSL, including:
- ECC key pair generation
- Hybrid encryption (AES + ECC)
- ECDH key exchange

## Prerequisites

1. Python 3.6 or higher
2. OpenSSL installed and available in your system PATH

## Directory Structure

```
ecc_demo/
├── keys/           # Stores generated ECC key pairs
├── encrypted/      # Stores encrypted files and keys
├── messages/       # Stores plaintext and decrypted messages
├── ecc_crypto.py   # Main implementation script
└── README.md       # This file
```

## Usage

1. Make sure you have OpenSSL installed and available in your system PATH.

2. Run the implementation:
   ```bash
   python ecc_crypto.py
   ```

The script will:
1. Generate ECC key pairs for Alice and Bob
2. Demonstrate message encryption and decryption
3. Perform ECDH key exchange between Alice and Bob

## Implementation Details

### Key Generation
- Uses OpenSSL's `ecparam` and `ec` commands
- Generates keys using the secp256k1 curve
- Outputs private and public keys in PEM format

### Hybrid Encryption
1. Generates a random AES-256 key
2. Encrypts the message using AES-256-CBC
3. Encrypts the AES key using the recipient's ECC public key
4. Decrypts the AES key using the recipient's private key
5. Uses the decrypted AES key to decrypt the message

### ECDH Key Exchange
- Demonstrates secure key exchange between two parties
- Shows that both parties derive the same shared secret
- Uses OpenSSL's `pkeyutl` command for key derivation

## Security Notes

1. The implementation uses secure defaults:
   - secp256k1 curve for ECC
   - AES-256-CBC for symmetric encryption
   - Proper key generation and management

2. In a production environment, you should:
   - Use proper key storage mechanisms
   - Implement proper error handling
   - Add additional security measures as needed

## Troubleshooting

If you encounter any issues:
1. Ensure OpenSSL is properly installed and in your PATH
2. Check file permissions in the working directory
3. Verify Python version compatibility 
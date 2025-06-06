# PHP Cryptography Implementations

This directory contains PHP implementations of various cryptographic algorithms, mirroring the Python implementations in the parent directory.

## Implemented Algorithms

1. Symmetric Encryption
   - AES-256-GCM
   - ChaCha20-Poly1305

2. Public Key Cryptography (Planned)
   - RSA
   - ECC (Elliptic Curve Cryptography)

3. Homomorphic Encryption (Planned)
   - Paillier Cryptosystem

## Requirements

- PHP 8.0 or higher
- OpenSSL extension
- Composer for dependency management

## Setup

1. Install dependencies:
```bash
composer install
```

2. Configure your web server (Apache/Nginx) to point to this directory

3. Make sure the following PHP extensions are enabled:
   - openssl
   - sodium (for ChaCha20-Poly1305)
   - gmp (for Paillier implementation)

## Security Notes

- These implementations are for educational purposes
- Always use well-tested cryptographic libraries in production
- Keep your keys secure and never expose them
- Use secure random number generation
- Follow PHP cryptography best practices 
# Advanced Symmetric Encryption Implementation

This project implements and compares two modern symmetric encryption algorithms:
- ChaCha20
- AES-GCM (Galois/Counter Mode)

## Setup

1. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the script:
```bash
python symmetric_encryption.py
```

## About the Implementations

### ChaCha20
- A modern stream cipher designed by Daniel J. Bernstein
- Uses a 256-bit key and 96-bit nonce
- Known for its high performance on software implementations
- No specialized hardware acceleration required
- Widely used in TLS 1.3 and other protocols

### AES-GCM
- Combines AES in counter mode with Galois authentication
- Provides both confidentiality and authenticity (authenticated encryption)
- Uses a 256-bit key and 96-bit nonce
- Authentication tag ensures message integrity
- Hardware acceleration available on modern processors

## Security Features

1. ChaCha20:
   - Strong security margin
   - No known practical attacks
   - Resistant to timing attacks
   - Simple implementation reduces risk of errors

2. AES-GCM:
   - Authenticated encryption (AEAD)
   - Widely analyzed and standardized
   - Hardware acceleration support
   - Provides integrity checking

## Performance Considerations

The script includes performance testing that compares:
- Encryption/decryption speed
- Throughput (MB/s)
- Verification of correct operation

Results may vary depending on:
- Hardware capabilities (AES-NI support)
- CPU architecture
- System load
- Data size

## Best Practices

- Always use unique nonces (never reuse them)
- Store authentication tags securely
- Use secure random number generation for keys
- Implement proper key management
- Handle errors appropriately 
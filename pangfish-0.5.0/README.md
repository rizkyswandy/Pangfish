# Python Twofish Library

A Python extension module for the Twofish encryption algorithm.

## Installation

```bash
pip install .
```

Or for development:

```bash
pip install -e .
```

## Usage

```python
import twofish

# Create a new Twofish instance with a 128-bit key
key = b"This is a 16-byte key"
cipher = twofish.Twofish(key)

# Single block encryption (16 bytes)
plaintext = b"This is a test!!"
ciphertext = cipher.encrypt_block(plaintext)
decrypted = cipher.decrypt_block(ciphertext)

# Multi-block encryption with ECB mode
long_text = b"This is a longer message that requires multiple blocks!"
encrypted = cipher.encrypt(long_text, mode='ecb')
decrypted = cipher.decrypt(encrypted, mode='ecb')

# Multi-block encryption with CBC mode
import os
iv = os.urandom(16)  # Generate random 16-byte IV
encrypted = cipher.encrypt(long_text, mode='cbc', iv=iv)
decrypted = cipher.decrypt(encrypted, mode='cbc', iv=iv)
```

## Features

- Efficient C implementation of the Twofish algorithm
- Support for 128, 192, and 256-bit keys
- ECB and CBC modes of operation
- PKCS#7 padding

## About Twofish

Twofish is a symmetric key block cipher with a block size of 128 bits and key sizes up to 256 bits. It was one of the five finalists of the Advanced Encryption Standard contest.

## Performance

This implementation is optimized for speed and leverages the original C implementation for maximum performance.
import twofish
import os

def test_twofish():
    # Test with 128-bit key
    key = b"This is a 16-byte key"
    cipher = twofish.Twofish(key)
    
    # Single block encryption
    plaintext = b"This is a test!!"  # Exactly 16 bytes
    ciphertext = cipher.encrypt_block(plaintext)
    decrypted = cipher.decrypt_block(ciphertext)
    
    print("=== Single Block Test ===")
    print(f"Original: {plaintext.decode('utf-8')}")
    print(f"Encrypted (hex): {ciphertext.hex()}")
    print(f"Decrypted: {decrypted.decode('utf-8')}")
    print()
    
    # Multi-block encryption with ECB mode
    long_text = b"This is a longer message that requires multiple blocks to encrypt properly!"
    encrypted_ecb = cipher.encrypt(long_text, mode='ecb')
    decrypted_ecb = cipher.decrypt(encrypted_ecb, mode='ecb')
    
    print("=== ECB Mode Test ===")
    print(f"Original: {long_text.decode('utf-8')}")
    print(f"Encrypted (hex): {encrypted_ecb.hex()}")
    print(f"Decrypted: {decrypted_ecb.decode('utf-8')}")
    print()
    
    # Multi-block encryption with CBC mode
    iv = os.urandom(16)  # Generate random IV
    encrypted_cbc = cipher.encrypt(long_text, mode='cbc', iv=iv)
    decrypted_cbc = cipher.decrypt(encrypted_cbc, mode='cbc', iv=iv)
    
    print("=== CBC Mode Test ===")
    print(f"Original: {long_text.decode('utf-8')}")
    print(f"IV (hex): {iv.hex()}")
    print(f"Encrypted (hex): {encrypted_cbc.hex()}")
    print(f"Decrypted: {decrypted_cbc.decode('utf-8')}")
    print()
    
    # Test different key sizes
    print("=== Testing Different Key Sizes ===")
    
    # 192-bit key
    key192 = b"This is a 24-byte key!!!!!!"
    cipher192 = twofish.Twofish(key192)
    ciphertext192 = cipher192.encrypt_block(plaintext)
    print(f"192-bit key ciphertext: {ciphertext192.hex()}")
    
    # 256-bit key
    key256 = b"This is a 32-byte key!!!!!!!!!!!!!!"
    cipher256 = twofish.Twofish(key256)
    ciphertext256 = cipher256.encrypt_block(plaintext)
    print(f"256-bit key ciphertext: {ciphertext256.hex()}")

if __name__ == "__main__":
    test_twofish()
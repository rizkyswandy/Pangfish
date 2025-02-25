"""
Python wrapper for Pangfish encryption algorithms.
This module includes Twofish encryption and a hybrid cryptosystem with Multi-Power RSA.
"""

import hashlib
from _twofish import Twofish as _Twofish
from .hybrid import HybridCryptosystem
from .c_multipowerrsa import MultiPowerRSA

def derive_key(key_material, size=16):
    """Convert any input to a valid key of specified size (16, 24, or 32 bytes)"""
    if isinstance(key_material, str):
        key_material = key_material.encode('utf-8')
    return hashlib.sha256(key_material).digest()[:size]

class Twofish:
    """
    Pangfish block cipher implementation.
    
    The Pangfish algorithm is a symmetric key block cipher with a block size of 128 bits
    and key sizes up to 256 bits.
    """
    
    def __init__(self, key, auto_derive=False):
        """
        Initialize Pangfish cipher with the given key.
        
        Args:
            key (bytes or str): Key for Pangfish (16, 24, or 32 bytes for 128, 192, or 256 bits)
            auto_derive (bool): Automatically derive a valid key from any input using SHA-256
        """
        if isinstance(key, str):
            key = key.encode('utf-8')
            
        if not isinstance(key, bytes):
            raise TypeError("Key must be bytes or string")
        
        if auto_derive:
            # Use closest valid key size
            if len(key) <= 16:
                size = 16  # 128 bits
            elif len(key) <= 24:
                size = 24  # 192 bits
            else:
                size = 32  # 256 bits
                
            key = derive_key(key, size)
        elif len(key) not in (16, 24, 32):
            raise ValueError("Key size must be 16, 24, or 32 bytes (128, 192, or 256 bits). "
                            "Use auto_derive=True to automatically create a valid key.")
            
        self._cipher = _Twofish(key)
    
    def encrypt_block(self, data):
        """
        Encrypt a single block of data.
        
        Args:
            data (bytes): 16-byte block to encrypt
            
        Returns:
            bytes: Encrypted 16-byte block
        """
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes")
            
        if len(data) != 16:
            raise ValueError("Data must be exactly 16 bytes")
            
        return self._cipher.encrypt(data)
    
    def decrypt_block(self, data):
        """
        Decrypt a single block of data.
        
        Args:
            data (bytes): 16-byte block to decrypt
            
        Returns:
            bytes: Decrypted 16-byte block
        """
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes")
            
        if len(data) != 16:
            raise ValueError("Data must be exactly 16 bytes")
            
        return self._cipher.decrypt(data)
    
    def encrypt(self, data, mode='ecb', iv=None, padding=True):
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes")
        
        original_length = len(data)
        
        # Always pad to full 16-byte blocks
        if padding:
            pad_length = 16 - (original_length % 16)
            if pad_length == 0:
                pad_length = 16
            data = data + bytes([pad_length]) * pad_length
        
        result = bytearray()
        
        if mode.lower() == 'ecb':
            for i in range(0, len(data), 16):
                block = data[i:i+16]
                encrypted_block = self.encrypt_block(block)
                result.extend(encrypted_block)
        
        elif mode.lower() == 'cbc':
            if iv is None:
                iv = os.urandom(16)
            
            if len(iv) != 16:
                raise ValueError("IV must be 16 bytes for CBC mode")
            
            result.extend(iv)
            prev_block = iv
            
            for i in range(0, len(data), 16):
                block = data[i:i+16]
                xored = bytes(a ^ b for a, b in zip(block, prev_block))
                encrypted_block = self.encrypt_block(xored)
                result.extend(encrypted_block)
                prev_block = encrypted_block
        
        return bytes(result)

    def decrypt(self, data, mode='ecb', iv=None, padding=True):
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes")
        
        if len(data) == 0 or len(data) % 16 != 0:
            raise ValueError("Encrypted data length must be a non-zero multiple of 16 bytes")
        
        result = bytearray()
        
        if mode.lower() == 'ecb':
            for i in range(0, len(data), 16):
                block = data[i:i+16]
                decrypted_block = self.decrypt_block(block)
                result.extend(decrypted_block)
        
        elif mode.lower() == 'cbc':
            if len(data) < 16:
                raise ValueError("CBC mode requires at least 16 bytes for IV")
            
            iv = data[:16]
            data = data[16:]
            
            prev_block = iv
            
            for i in range(0, len(data), 16):
                block = data[i:i+16]
                decrypted_block = self.decrypt_block(block)
                xored = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
                result.extend(xored)
                prev_block = block
        
        # Remove padding if requested
        if padding and result:
            pad_length = result[-1]
            if 0 < pad_length <= 16:
                if all(x == pad_length for x in result[-pad_length:]):
                    result = result[:-pad_length]
        
        return bytes(result)

# Utility functions
def new(key, auto_derive=False):
    """
    Create a new Pangfish cipher instance.
    
    Args:
        key (bytes or str): Key for Pangfish (16, 24, or 32 bytes for 128, 192, or 256 bits)
        auto_derive (bool): Automatically derive a valid key from any input using SHA-256
        
    Returns:
        Twofish: A new Pangfish cipher instance
    """
    return Twofish(key, auto_derive)

def new_hybrid_cryptosystem():
    """
    Create a new hybrid cryptosystem using Twofish and Multi-Power RSA.
    
    Returns:
        HybridCryptosystem: A new hybrid cryptosystem instance
    """
    return HybridCryptosystem()

# Expose the MultiPowerRSA class for direct use
RSA = MultiPowerRSA
"""
Python wrapper for the C implementation of Multi-Power RSA.
"""

from _multipowerrsa import MPRSA as _MPRSA

class MultiPowerRSA:
    """
    Multi-Power RSA implementation using C for improved performance.
    
    This class provides a high-performance implementation of the Multi-Power RSA algorithm,
    which uses a modulus of the form N = p^(b-1) * q for more efficient decryption.
    """
    
    def __init__(self, key_size=2048, b=3):
        """
        Initialize a Multi-Power RSA instance.
        
        Args:
            key_size (int): Size of the key in bits
            b (int): Power value for p (default 3, so modulus is p²q)
        """
        self._rsa = _MPRSA(key_size, b)
        self.public_key = None
        self.private_key = None
        
    def generate_keys(self):
        """
        Generate a new RSA key pair.
        
        Returns:
            tuple: (public_key, private_key)
        """
        self.public_key, self.private_key = self._rsa.generate_keys()
        return self.public_key, self.private_key
        
    def encrypt(self, message, public_key=None):
        """
        Encrypt a message using Multi-Power RSA.
        
        Args:
            message: The message to encrypt (int, bytes, or string)
            public_key (bytes, optional): The public key to use for encryption
            
        Returns:
            str: The encrypted message as a string representation of a large integer
        """
        return self._rsa.encrypt(message, public_key or self.public_key)
        
    def decrypt(self, ciphertext, private_key=None):
        """
        Decrypt a message using Multi-Power RSA.
        
        Args:
            ciphertext: The encrypted message (string or int)
            private_key (bytes, optional): The private key to use for decryption
            
        Returns:
            int: The decrypted message as an integer
        """
        return self._rsa.decrypt(ciphertext, private_key or self.private_key)
        
    def decrypt_to_bytes(self, ciphertext, private_key=None):
        """
        Decrypt a message and return it as bytes.
        
        Args:
            ciphertext: The encrypted message (string or int)
            private_key (bytes, optional): The private key to use for decryption
            
        Returns:
            bytes: The decrypted message as bytes
        """
        return self._rsa.decrypt_to_bytes(ciphertext, private_key or self.private_key)
    
    @staticmethod
    def bytes_to_int(data):
        """
        Convert bytes to an integer.
        
        Args:
            data (bytes): Bytes to convert
            
        Returns:
            int: Integer representation of the bytes
        """
        return int.from_bytes(data, byteorder='big')
    
    @staticmethod
    def int_to_bytes(value, length=None):
        """
        Convert an integer to bytes.
        
        Args:
            value (int): Integer to convert
            length (int, optional): Length of the output in bytes
            
        Returns:
            bytes: Byte representation of the integer
        """
        if length is None:
            length = (value.bit_length() + 7) // 8
        return value.to_bytes(length, byteorder='big')
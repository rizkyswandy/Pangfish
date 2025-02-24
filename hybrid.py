"""
Hybrid Cryptosystem implementation combining Twofish and Multi-Power RSA
"""

import os
import secrets
import base64
import json
from c_multipowerrsa import MultiPowerRSA

class HybridCryptosystem:
    def __init__(self):
        """Initialize the hybrid cryptosystem"""
        self.twofish = None
        self.rsa = None
        
    def generate_keys(self, rsa_key_size=2048, b=3):
        """
        Generate RSA key pair for the hybrid cryptosystem
        
        Args:
            rsa_key_size (int): Size of RSA key in bits
            b (int): Power parameter for Multi-Power RSA (default 3)
            
        Returns:
            tuple: (public_key, private_key)
        """
        self.rsa = MultiPowerRSA(key_size=rsa_key_size, b=b)
        return self.rsa.generate_keys()
    
    def encrypt(self, plaintext, twofish_key=None, public_key=None):
        """
        Encrypt a message using the hybrid cryptosystem
        
        Args:
            plaintext (bytes): Message to encrypt
            twofish_key (bytes, optional): Symmetric key for Twofish (generated if None)
            public_key (bytes, optional): RSA public key
            
        Returns:
            dict: Dictionary containing the encrypted data and metadata
        """
        # Import pangfish here to avoid circular imports
        from pangfish import Twofish
        
        if twofish_key is None:
            twofish_key = secrets.token_bytes(32)  # 256-bit key
        
        # Print debug information
        print(f"Original plaintext length: {len(plaintext)}")
        
        # Create Twofish cipher and encrypt the plaintext
        cipher = Twofish(twofish_key)
        ciphertext = cipher.encrypt(plaintext, mode='cbc', iv=os.urandom(16))
        
        print(f"Encrypted ciphertext length: {len(ciphertext)}")
        
        # If public key is not provided, use the one from the object
        if public_key is None:
            if self.rsa is None or self.rsa.public_key is None:
                raise ValueError("No public key available. Generate or provide keys first.")
            public_key = self.rsa.public_key
        
        # Initialize RSA if not already done
        if self.rsa is None:
            self.rsa = MultiPowerRSA()
        
        # Encrypt the Twofish key with RSA
        key_int = MultiPowerRSA.bytes_to_int(twofish_key)
        encrypted_key = self.rsa.encrypt(key_int, public_key)
        
        # Prepare the output format
        # Extract iv from the beginning of ciphertext (first 16 bytes for CBC mode)
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        
        result = {
            "algorithm": "Twofish-MultiPowerRSA",
            "ciphertext": base64.b64encode(actual_ciphertext).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8'),
            "encrypted_key": encrypted_key
        }
        
        return result
    
    def decrypt(self, encrypted_data, private_key=None):
        """
        Decrypt a message using the hybrid cryptosystem
        
        Args:
            encrypted_data (dict): Dictionary containing the encrypted data and metadata
            private_key (bytes, optional): RSA private key
            
        Returns:
            bytes: Decrypted plaintext
        """
        # Import pangfish here to avoid circular imports
        from pangfish import Twofish
        
        # Validate input format
        required_fields = ["algorithm", "ciphertext", "iv", "encrypted_key"]
        if not all(field in encrypted_data for field in required_fields):
            raise ValueError("Invalid encrypted data format")
        
        # Check algorithm
        if encrypted_data["algorithm"] != "Twofish-MultiPowerRSA":
            raise ValueError(f"Unsupported algorithm: {encrypted_data['algorithm']}")
        
        # Extract components
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        iv = base64.b64decode(encrypted_data["iv"])
        encrypted_key = encrypted_data["encrypted_key"]
        
        print(f"Encrypted ciphertext length: {len(ciphertext)}")
        print(f"IV length: {len(iv)}")
        
        # If private key is not provided, use the one from the object
        if private_key is None:
            if self.rsa is None or self.rsa.private_key is None:
                raise ValueError("No private key available. Generate or provide keys first.")
            private_key = self.rsa.private_key
        
        # Initialize RSA if not already done
        if self.rsa is None:
            self.rsa = MultiPowerRSA()
        
        # Decrypt the Twofish key
        key_int = self.rsa.decrypt(encrypted_key, private_key)
        twofish_key = MultiPowerRSA.int_to_bytes(key_int)
        
        # Create Twofish cipher and decrypt the ciphertext
        cipher = Twofish(twofish_key)
        
        # Reconstruct the full ciphertext with IV
        full_ciphertext = iv + ciphertext
        
        # Decrypt the message
        plaintext = cipher.decrypt(full_ciphertext, mode='cbc', iv=iv)
        
        return plaintext
    
    @staticmethod
    def serialize_encrypted_data(encrypted_data):
        """Convert encrypted data dictionary to JSON string"""
        return json.dumps(encrypted_data)
    
    @staticmethod
    def deserialize_encrypted_data(json_data):
        """Convert JSON string to encrypted data dictionary"""
        return json.loads(json_data)
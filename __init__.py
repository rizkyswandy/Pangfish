"""
Pangfish - A hybrid cryptosystem library implementing Twofish and Multi-Power RSA
"""

from .pangfish import (
    Twofish, 
    derive_key, 
    new
)

from .c_multipowerrsa import MultiPowerRSA
from .hybrid import HybridCryptosystem

def new_hybrid_cryptosystem():
    """
    Create a new hybrid cryptosystem using Twofish and Multi-Power RSA.
    
    Returns:
        HybridCryptosystem: A new hybrid cryptosystem instance
    """
    return HybridCryptosystem()

# Alias for backwards compatibility
RSA = MultiPowerRSA

__version__ = '0.2.0'
__all__ = [
    'Twofish', 
    'derive_key', 
    'new', 
    'new_hybrid_cryptosystem',
    'RSA',
    'MultiPowerRSA',
    'HybridCryptosystem'
]
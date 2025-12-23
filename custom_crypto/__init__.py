"""
Custom Cryptography Library - Hand-Implemented Primitives

This module contains from-scratch implementations of various cryptographic
algorithms for educational and research purposes.

Available modules:
- caesar: Caesar cipher with frequency analysis breaker
- vigenere: Vigenère cipher with Kasiski examination
- sha256: Simplified SHA-256 hash function
- merkle: Merkle tree construction and proofs
- rsa: RSA key generation and operations
- aes: AES key expansion algorithm

Note: These implementations are for educational purposes only and should not
be used in production security-critical applications.
"""

__version__ = "1.0.0"
__all__ = ["caesar", "vigenere", "sha256", "merkle", "rsa", "aes"]

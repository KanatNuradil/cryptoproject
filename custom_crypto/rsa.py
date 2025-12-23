"""
RSA Cryptography Implementation

This module implements RSA key generation, encryption, and decryption
from scratch, including prime finding and modular arithmetic operations.

Note: This is for educational purposes only and should not be used
in production security-critical applications.
"""

import random
from typing import Tuple


def _is_prime(n: int, k: int = 5) -> bool:
    """
    Miller-Rabin primality test.

    Args:
        n: Number to test for primality
        k: Number of rounds for accuracy

    Returns:
        True if n is likely prime
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Write n as d*2^r + 1
    r = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    # Witness loop
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def _generate_prime(bits: int) -> int:
    """
    Generate a random prime number with specified bit length.

    Args:
        bits: Number of bits for the prime

    Returns:
        Prime number
    """
    while True:
        # Generate random odd number
        num = random.getrandbits(bits) | 1

        # Ensure it's in the right range
        num |= (1 << (bits - 1))  # Set MSB
        num |= 1  # Ensure odd

        if _is_prime(num):
            return num


def _mod_inverse(a: int, m: int) -> int:
    """
    Compute modular inverse using Extended Euclidean Algorithm.

    Args:
        a: Number to find inverse for
        m: Modulus

    Returns:
        Modular inverse of a modulo m
    """
    m0, y, x = m, 0, 1
    if m == 1:
        return 0

    while a > 1:
        q = a // m
        m, a = a % m, m
        y, x = x - q * y, y

    if x < 0:
        x += m0

    return x


def generate_keypair(bits: int = 2048) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """
    Generate RSA key pair.

    Args:
        bits: Key size in bits (default 2048)

    Returns:
        Tuple of (public_key, private_key)
        public_key = (n, e)
        private_key = (n, d)
    """
    # Generate two distinct primes
    p = _generate_prime(bits // 2)
    q = _generate_prime(bits // 2)

    # Ensure p != q
    while p == q:
        q = _generate_prime(bits // 2)

    # Compute n = p * q
    n = p * q

    # Compute φ(n) = (p-1)*(q-1)
    phi = (p - 1) * (q - 1)

    # Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
    e = 65537  # Common choice for e

    # Verify e and φ(n) are coprime
    if _gcd(e, phi) != 1:
        # Fallback: try 3
        e = 3
        if _gcd(e, phi) != 1:
            raise ValueError("Could not find suitable e")

    # Compute d = e^(-1) mod φ(n)
    d = _mod_inverse(e, phi)

    public_key = (n, e)
    private_key = (n, d)

    return public_key, private_key


def _gcd(a: int, b: int) -> int:
    """Compute greatest common divisor using Euclidean algorithm."""
    while b != 0:
        a, b = b, a % b
    return a


def encrypt(message: int, public_key: Tuple[int, int]) -> int:
    """
    Encrypt a message using RSA public key.

    Args:
        message: Integer message to encrypt (must be < n)
        public_key: (n, e) tuple

    Returns:
        Encrypted ciphertext
    """
    n, e = public_key

    if message >= n:
        raise ValueError("Message too large for key")

    return pow(message, e, n)


def decrypt(ciphertext: int, private_key: Tuple[int, int]) -> int:
    """
    Decrypt a ciphertext using RSA private key.

    Args:
        ciphertext: Integer ciphertext to decrypt
        private_key: (n, d) tuple

    Returns:
        Decrypted plaintext
    """
    n, d = private_key
    return pow(ciphertext, d, n)


def sign(message: int, private_key: Tuple[int, int]) -> int:
    """
    Sign a message using RSA private key.

    Args:
        message: Integer message to sign
        private_key: (n, d) tuple

    Returns:
        Digital signature
    """
    return decrypt(message, private_key)  # Same as decryption


def verify(signature: int, message: int, public_key: Tuple[int, int]) -> bool:
    """
    Verify an RSA signature.

    Args:
        signature: Digital signature
        message: Original message
        public_key: (n, e) tuple

    Returns:
        True if signature is valid
    """
    decrypted = encrypt(signature, public_key)
    return decrypted == message


# Example usage and testing
if __name__ == "__main__":
    print("Generating RSA key pair (512 bits for demo)...")
    public_key, private_key = generate_keypair(512)

    print(f"Public key: (n={public_key[0]}, e={public_key[1]})")
    print(f"Private key: (n={private_key[0]}, d={private_key[1]})")

    # Test encryption/decryption
    message = 12345
    print(f"\nOriginal message: {message}")

    encrypted = encrypt(message, public_key)
    print(f"Encrypted: {encrypted}")

    decrypted = decrypt(encrypted, private_key)
    print(f"Decrypted: {decrypted}")

    print(f"Success: {message == decrypted}")

    # Test digital signature
    print("
Testing digital signature...")
    signature = sign(message, private_key)
    print(f"Signature: {signature}")

    is_valid = verify(signature, message, public_key)
    print(f"Signature valid: {is_valid}")

    # Test with wrong message
    is_valid_wrong = verify(signature, message + 1, public_key)
    print(f"Wrong message signature valid: {is_valid_wrong}")</content>

"""
Simplified SHA-256 Hash Function Implementation

This module implements a simplified version of the SHA-256 hash function
from scratch. While not a full production implementation, it demonstrates
the core principles of the SHA-256 algorithm.

Note: This is for educational purposes only and should not be used
in security-critical applications.
"""

from typing import List


# SHA-256 constants
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# Initial hash values
H0 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]


def _right_rotate(value: int, amount: int) -> int:
    """Rotate a 32-bit integer right by the specified amount."""
    return ((value >> amount) | (value << (32 - amount))) & 0xFFFFFFFF


def _right_shift(value: int, amount: int) -> int:
    """Right shift a 32-bit integer."""
    return value >> amount


def _choice(x: int, y: int, z: int) -> int:
    """Choice function: (x & y) ^ (~x & z)"""
    return (x & y) ^ (~x & z)


def _majority(x: int, y: int, z: int) -> int:
    """Majority function: (x & y) ^ (x & z) ^ (y & z)"""
    return (x & y) ^ (x & z) ^ (y & z)


def _sigma0(x: int) -> int:
    """Σ0 function: right_rotate(x, 2) ^ right_rotate(x, 13) ^ right_rotate(x, 22)"""
    return _right_rotate(x, 2) ^ _right_rotate(x, 13) ^ _right_rotate(x, 22)


def _sigma1(x: int) -> int:
    """Σ1 function: right_rotate(x, 6) ^ right_rotate(x, 11) ^ right_rotate(x, 25)"""
    return _right_rotate(x, 6) ^ _right_rotate(x, 11) ^ _right_rotate(x, 25)


def _gamma0(x: int) -> int:
    """γ0 function: right_rotate(x, 7) ^ right_rotate(x, 18) ^ right_shift(x, 3)"""
    return _right_rotate(x, 7) ^ _right_rotate(x, 18) ^ _right_shift(x, 3)


def _gamma1(x: int) -> int:
    """γ1 function: right_rotate(x, 17) ^ right_rotate(x, 19) ^ right_shift(x, 10)"""
    return _right_rotate(x, 17) ^ _right_rotate(x, 19) ^ _right_shift(x, 10)


def _pad_message(message: bytes) -> bytes:
    """Pad the message according to SHA-256 specification."""
    msg_len = len(message) * 8  # Length in bits

    # Append '1' bit
    padded = message + b'\x80'

    # Append zeros until length ≡ 56 (mod 64)
    while (len(padded) % 64) != 56:
        padded += b'\x00'

    # Append original length as 64-bit big-endian
    padded += msg_len.to_bytes(8, 'big')

    return padded


def _create_message_schedule(chunk: bytes) -> List[int]:
    """Create the message schedule W[0..63] from a 512-bit chunk."""
    # Break chunk into sixteen 32-bit big-endian words
    w = []
    for i in range(0, 64, 4):
        word = int.from_bytes(chunk[i:i+4], 'big')
        w.append(word)

    # Extend to 64 words
    for i in range(16, 64):
        s0 = _gamma0(w[i-15])
        s1 = _gamma1(w[i-2])
        w.append((w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF)

    return w


def _compress_chunk(h: List[int], chunk: bytes) -> List[int]:
    """Compress a single 512-bit chunk and update hash values."""
    w = _create_message_schedule(chunk)
    a, b, c, d, e, f, g, h_val = h

    # Main compression loop
    for i in range(64):
        s1 = _sigma1(e)
        ch = _choice(e, f, g)
        temp1 = (h_val + s1 + ch + K[i] + w[i]) & 0xFFFFFFFF

        s0 = _sigma0(a)
        maj = _majority(a, b, c)
        temp2 = (s0 + maj) & 0xFFFFFFFF

        h_val = g
        g = f
        f = e
        e = (d + temp1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xFFFFFFFF

    # Add compressed chunk to current hash value
    return [
        (h[0] + a) & 0xFFFFFFFF,
        (h[1] + b) & 0xFFFFFFFF,
        (h[2] + c) & 0xFFFFFFFF,
        (h[3] + d) & 0xFFFFFFFF,
        (h[4] + e) & 0xFFFFFFFF,
        (h[5] + f) & 0xFFFFFFFF,
        (h[6] + g) & 0xFFFFFFFF,
        (h[7] + h_val) & 0xFFFFFFFF,
    ]


def hash(message: str) -> str:
    """
    Compute SHA-256 hash of a message.

    Args:
        message: Input message string

    Returns:
        Hexadecimal string representation of the hash
    """
    # Convert string to bytes
    message_bytes = message.encode('utf-8')

    # Pad the message
    padded = _pad_message(message_bytes)

    # Initialize hash values
    h = H0.copy()

    # Process message in 512-bit chunks
    for i in range(0, len(padded), 64):
        chunk = padded[i:i+64]
        h = _compress_chunk(h, chunk)

    # Produce final hash as hex string
    return ''.join(f'{x:08x}' for x in h)


# Example usage
if __name__ == "__main__":
    test_messages = [
        "",
        "a",
        "abc",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "The quick brown fox jumps over the lazy dog"
    ]

    print("SHA-256 Test Vectors:")
    for msg in test_messages:
        hash_value = hash(msg)
        print(f"Message: '{msg}'")
        print(f"Hash: {hash_value}")
        print()

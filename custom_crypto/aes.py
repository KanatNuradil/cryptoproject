"""
AES Key Expansion Algorithm

This module implements the AES key expansion algorithm from scratch.
It generates round keys from the initial cipher key for AES encryption.

Note: This is for educational purposes only and should not be used
in production security-critical applications.
"""

from typing import List


# AES S-box (substitution box)
S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

# Round constants for key expansion
R_CON = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A
]


def _sub_word(word: int) -> int:
    """
    Apply S-box substitution to each byte of a 32-bit word.

    Args:
        word: 32-bit word

    Returns:
        Transformed 32-bit word
    """
    result = 0
    for i in range(4):
        byte = (word >> (i * 8)) & 0xFF
        substituted = S_BOX[byte]
        result |= (substituted << (i * 8))
    return result


def _rot_word(word: int) -> int:
    """
    Rotate a 32-bit word left by 8 bits (1 byte).

    Args:
        word: 32-bit word

    Returns:
        Rotated 32-bit word
    """
    return ((word << 8) & 0xFFFFFFFF) | (word >> 24)


def _xor_words(word1: int, word2: int) -> int:
    """
    XOR two 32-bit words.

    Args:
        word1: First 32-bit word
        word2: Second 32-bit word

    Returns:
        XOR result
    """
    return word1 ^ word2


def key_expansion(key: bytes) -> List[List[int]]:
    """
    Generate round keys for AES from the cipher key.

    This implements the AES key expansion algorithm.

    Args:
        key: Cipher key (16 bytes for AES-128, 24 bytes for AES-192, 32 bytes for AES-256)

    Returns:
        List of round keys, each containing 4 32-bit words
    """
    key_length = len(key)

    if key_length not in [16, 24, 32]:
        raise ValueError("Key length must be 16, 24, or 32 bytes")

    # Determine number of 32-bit words in key and rounds
    if key_length == 16:  # AES-128
        nk = 4  # Number of 32-bit words in key
        nr = 10  # Number of rounds
    elif key_length == 24:  # AES-192
        nk = 6
        nr = 12
    else:  # AES-256
        nk = 8
        nr = 14

    # Convert key bytes to array of 32-bit words
    w = []
    for i in range(nk):
        word = 0
        for j in range(4):
            word |= (key[i * 4 + j] << (j * 8))
        w.append(word)

    # Generate additional words
    for i in range(nk, 4 * (nr + 1)):
        temp = w[i - 1]

        if i % nk == 0:
            # Apply RotWord, SubWord, and XOR with Rcon
            temp = _sub_word(_rot_word(temp))
            rcon_value = R_CON[i // nk] << 24  # Rcon in MSB
            temp ^= rcon_value
        elif nk > 6 and i % nk == 4:
            # Additional SubWord for AES-256
            temp = _sub_word(temp)

        # XOR with word nk positions back
        temp ^= w[i - nk]
        w.append(temp)

    # Group words into round keys (each round key has 4 words)
    round_keys = []
    for i in range(0, len(w), 4):
        round_keys.append(w[i:i + 4])

    return round_keys


def get_round_key(round_keys: List[List[int]], round_num: int) -> List[int]:
    """
    Get the round key for a specific round.

    Args:
        round_keys: All round keys from key expansion
        round_num: Round number (0 for initial key)

    Returns:
        Round key as list of 4 32-bit words
    """
    if round_num >= len(round_keys):
        raise ValueError(f"Round number {round_num} exceeds available rounds")
    return round_keys[round_num]


# Example usage and testing
if __name__ == "__main__":
    # Test with AES-128 key
    key_128 = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c'
    print("AES-128 Key Expansion Test")
    print(f"Key: {key_128.hex()}")

    round_keys_128 = key_expansion(key_128)
    print(f"Number of round keys: {len(round_keys_128)}")

    # Show first few round keys
    for i in range(min(3, len(round_keys_128))):
        key_words = [f"{word:08x}" for word in round_keys_128[i]]
        print(f"Round {i} key: {' '.join(key_words)}")

    # Test with AES-256 key
    key_256 = b'\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4'
    print("\nAES-256 Key Expansion Test")
    print(f"Key: {key_256.hex()}")

    round_keys_256 = key_expansion(key_256)
    print(f"Number of round keys: {len(round_keys_256)}")

    # Show first few round keys
    for i in range(min(3, len(round_keys_256))):
        key_words = [f"{word:08x}" for word in round_keys_256[i]]
        print(f"Round {i} key: {' '.join(key_words)}")

    print("\nKey expansion completed successfully!")

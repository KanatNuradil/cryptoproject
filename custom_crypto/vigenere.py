"""
Vigenère Cipher with Kasiski Examination

This module implements the Vigenère cipher encryption/decryption algorithm
along with cryptanalysis tools including Kasiski examination and frequency
analysis for breaking the cipher automatically.

The Vigenère cipher is a polyalphabetic substitution cipher that uses a
keyword to determine shift amounts for each letter in the plaintext.
"""

import string
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Set
import re


def _normalize_text(text: str) -> str:
    """Normalize text by converting to uppercase and removing non-alphabetic characters."""
    return ''.join(char.upper() for char in text if char.isalpha())


def encrypt(plaintext: str, key: str) -> str:
    """
    Encrypt plaintext using Vigenère cipher with given key.

    Args:
        plaintext: Text to encrypt
        key: Keyword for encryption (alphabetic characters only)

    Returns:
        Encrypted ciphertext

    Raises:
        ValueError: If key contains non-alphabetic characters
    """
    if not key or not all(char.isalpha() for char in key):
        raise ValueError("Key must contain only alphabetic characters")

    normalized_plaintext = _normalize_text(plaintext)
    normalized_key = _normalize_text(key)

    if not normalized_plaintext:
        return ""

    result = []
    key_index = 0

    for char in normalized_plaintext:
        if char.isalpha():
            # Calculate shift based on key character
            key_char = normalized_key[key_index % len(normalized_key)]
            shift = ord(key_char) - ord('A')

            # Apply Vigenère encryption
            encrypted = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            result.append(encrypted)

            key_index += 1
        else:
            # Keep non-alphabetic characters (though we normalize them out)
            result.append(char)

    return ''.join(result)


def decrypt(ciphertext: str, key: str) -> str:
    """
    Decrypt ciphertext using Vigenère cipher with given key.

    Args:
        ciphertext: Text to decrypt
        key: Keyword for decryption (alphabetic characters only)

    Returns:
        Decrypted plaintext

    Raises:
        ValueError: If key contains non-alphabetic characters
    """
    if not key or not all(char.isalpha() for char in key):
        raise ValueError("Key must contain only alphabetic characters")

    normalized_ciphertext = _normalize_text(ciphertext)
    normalized_key = _normalize_text(key)

    if not normalized_ciphertext:
        return ""

    result = []
    key_index = 0

    for char in normalized_ciphertext:
        if char.isalpha():
            # Calculate shift based on key character
            key_char = normalized_key[key_index % len(normalized_key)]
            shift = ord(key_char) - ord('A')

            # Apply Vigenère decryption
            decrypted = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            result.append(decrypted)

            key_index += 1
        else:
            result.append(char)

    return ''.join(result)


def kasiski_examination(ciphertext: str, min_length: int = 3, max_length: int = 10) -> List[Tuple[int, int]]:
    """
    Perform Kasiski examination to find potential key lengths.

    This method looks for repeated sequences in the ciphertext and analyzes
    the distances between them to determine likely key lengths.

    Args:
        ciphertext: Encrypted text to analyze
        min_length: Minimum sequence length to consider
        max_length: Maximum sequence length to consider

    Returns:
        List of tuples: (key_length, score) sorted by score descending
    """
    normalized_text = _normalize_text(ciphertext)
    if len(normalized_text) < min_length * 2:
        return []

    # Find repeated sequences
    sequences = {}
    for length in range(min_length, min(max_length + 1, len(normalized_text) // 2 + 1)):
        for i in range(len(normalized_text) - length + 1):
            seq = normalized_text[i:i + length]
            if seq not in sequences:
                sequences[seq] = []
            sequences[seq].append(i)

    # Calculate spacings between repeated sequences
    spacings = []
    for seq, positions in sequences.items():
        if len(positions) >= 2:
            for i in range(len(positions) - 1):
                spacing = positions[i + 1] - positions[i]
                spacings.append(spacing)

    if not spacings:
        return []

    # Find factors of spacings (potential key lengths)
    factors_count = defaultdict(int)
    for spacing in spacings:
        # Find factors from 2 to min(spacing, 20) to avoid too long keys
        for factor in range(2, min(spacing + 1, 21)):
            if spacing % factor == 0:
                factors_count[factor] += 1

    # Sort by frequency (most common factors first)
    key_candidates = sorted(factors_count.items(), key=lambda x: x[1], reverse=True)

    # Return top candidates with their scores
    return key_candidates[:10]


def _calculate_ic(text: str) -> float:
    """
    Calculate Index of Coincidence for text.

    The IoC measures how likely letters are to be repeated, which helps
    distinguish between monoalphabetic and polyalphabetic ciphers.

    Args:
        text: Text to analyze

    Returns:
        Index of Coincidence value
    """
    if len(text) <= 1:
        return 0.0

    frequencies = Counter(text)
    ic = 0.0

    for count in frequencies.values():
        ic += count * (count - 1)

    ic /= len(text) * (len(text) - 1)
    return ic


def find_key_length_ic(ciphertext: str, max_key_length: int = 20) -> List[Tuple[int, float]]:
    """
    Find likely key lengths using Index of Coincidence analysis.

    This method tries different key lengths and calculates the average IoC
    for each subgroup. Higher IoC values suggest better key length matches.

    Args:
        ciphertext: Encrypted text to analyze
        max_key_length: Maximum key length to test

    Returns:
        List of tuples: (key_length, average_ic) sorted by IC descending
    """
    normalized_text = _normalize_text(ciphertext)
    if len(normalized_text) < max_key_length:
        return []

    results = []

    for key_length in range(2, min(max_key_length + 1, len(normalized_text))):
        # Divide text into key_length subgroups
        subgroups = ['' for _ in range(key_length)]

        for i, char in enumerate(normalized_text):
            subgroups[i % key_length] += char

        # Calculate average Index of Coincidence
        total_ic = 0.0
        valid_subgroups = 0

        for subgroup in subgroups:
            if len(subgroup) > 1:  # Need at least 2 characters for IC
                ic = _calculate_ic(subgroup)
                total_ic += ic
                valid_subgroups += 1

        if valid_subgroups > 0:
            avg_ic = total_ic / valid_subgroups
            results.append((key_length, avg_ic))

    # Sort by average IC (higher = more likely key length)
    results.sort(key=lambda x: x[1], reverse=True)

    return results[:10]


def frequency_analysis(ciphertext: str, key_length: int, num_candidates: int = 5) -> List[str]:
    """
    Perform frequency analysis on ciphertext assuming given key length.

    This method divides the ciphertext into key_length subgroups and
    performs Caesar cipher frequency analysis on each.

    Args:
        ciphertext: Encrypted text to analyze
        key_length: Assumed key length
        num_candidates: Number of key candidates to return

    Returns:
        List of potential keys (strings)
    """
    from .caesar import frequency_analysis as caesar_break

    normalized_text = _normalize_text(ciphertext)
    if len(normalized_text) < key_length or key_length < 1:
        return []

    # Divide into subgroups
    subgroups = ['' for _ in range(key_length)]
    for i, char in enumerate(normalized_text):
        subgroups[i % key_length] += char

    # Find most likely key characters for each position
    key_candidates = []

    for subgroup in subgroups:
        if len(subgroup) < 10:  # Need minimum text for analysis
            key_candidates.append('A')  # Default fallback
            continue

        # Use Caesar cipher breaker on this subgroup
        candidates = caesar_break(subgroup, 1)  # Get best candidate
        if candidates:
            best_shift, _, _ = candidates[0]
            # Convert shift back to key character
            # If subgroup was encrypted with key char K, then shift = ord(K) - ord('A')
            # So K = chr(shift + ord('A'))
            key_char = chr(best_shift + ord('A'))
            key_candidates.append(key_char)
        else:
            key_candidates.append('A')

    # Generate key candidates by trying variations
    candidates = [''.join(key_candidates)]

    # Try shifting each position by small amounts to find better matches
    for pos in range(len(key_candidates)):
        for shift in [-1, 1, -2, 2]:  # Try small shifts
            test_key = list(key_candidates)
            test_key[pos] = chr((ord(test_key[pos]) - ord('A') + shift) % 26 + ord('A'))
            candidates.append(''.join(test_key))

    # Remove duplicates and return top candidates
    unique_candidates = list(set(candidates))[:num_candidates]

    return unique_candidates


def brute_force_attack(ciphertext: str, key_lengths: List[int] = None) -> Dict[int, List[Tuple[str, str]]]:
    """
    Try brute force attack with common keywords.

    Args:
        ciphertext: Text to decrypt
        key_lengths: Specific key lengths to try (optional)

    Returns:
        Dictionary mapping key lengths to lists of (key, decrypted_text) tuples
    """
    if key_lengths is None:
        key_lengths = [3, 4, 5, 6, 7, 8, 9, 10]

    # Common English words that might be used as keys
    common_keys = [
        "THE", "AND", "FOR", "ARE", "BUT", "NOT", "YOU", "ALL", "CAN", "HER",
        "WAS", "ONE", "OUR", "HAD", "BY", "WORD", "HOW", "SAID", "EACH", "WHICH",
        "THEIR", "TIME", "WILL", "ABOUT", "MANY", "THEN", "THEM", "WRITE", "WOULD",
        "LIKE", "LONG", "MAKE", "THING", "HAVE", "LOOK", "MORE", "DAY", "COULD",
        "GO", "COME", "DID", "NUMBER", "SOUND", "WATER", "THAN", "FIRST", "PEOPLE"
    ]

    results = {}

    for key_length in key_lengths:
        if key_length > len(common_keys[0]):  # Skip if key would be longer than available words
            continue

        length_results = []
        tested_keys = set()

        for key in common_keys:
            if len(key) == key_length and key not in tested_keys:
                try:
                    decrypted = decrypt(ciphertext, key)
                    length_results.append((key, decrypted))
                    tested_keys.add(key)
                except:
                    continue

        if length_results:
            results[key_length] = length_results[:10]  # Limit results

    return results


def detect_vigenere_cipher(text: str) -> bool:
    """
    Simple heuristic to detect if text might be Vigenère cipher encrypted.

    Args:
        text: Text to analyze

    Returns:
        True if text might be Vigenère cipher encrypted
    """
    if len(text) < 50:  # Need sufficient text for analysis
        return False

    normalized_text = _normalize_text(text)

    # Check Index of Coincidence - should be higher than random but lower than monoalphabetic
    ic = _calculate_ic(normalized_text)
    english_ic = 0.067  # Typical English IoC

    # Vigenère typically has IoC between 0.04 and 0.06
    if not (0.04 <= ic <= 0.06):
        return False

    # Look for repeated patterns at different intervals
    pattern_found = False
    for length in range(3, 8):
        patterns = {}
        for i in range(len(normalized_text) - length + 1):
            seq = normalized_text[i:i + length]
            if seq in patterns:
                if i - patterns[seq] > length:  # Not overlapping
                    pattern_found = True
                    break
            else:
                patterns[seq] = i

        if pattern_found:
            break

    return pattern_found


# Example usage and testing
if __name__ == "__main__":
    # Example encryption/decryption
    plaintext = "ATTACKATDAWN"
    key = "LEMON"

    encrypted = encrypt(plaintext, key)
    decrypted = decrypt(encrypted, key)

    print(f"Plaintext: {plaintext}")
    print(f"Key: {key}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    print()

    # Kasiski examination
    print("Kasiski examination results:")
    key_length_candidates = kasiski_examination(encrypted)
    for length, score in key_length_candidates[:5]:
        print(f"Key length {length}: {score} occurrences")

    print()

    # Index of Coincidence analysis
    print("Index of Coincidence analysis:")
    ic_candidates = find_key_length_ic(encrypted)
    for length, avg_ic in ic_candidates[:5]:
        print(f"Key length {length}: average IC {avg_ic:.4f}")

    print()

    # Frequency analysis attack
    likely_key_lengths = [length for length, _ in key_length_candidates[:3]]
    if likely_key_lengths:
        best_length = likely_key_lengths[0]
        print(f"Attempting frequency analysis with key length {best_length}:")
        key_candidates = frequency_analysis(encrypted, best_length, 3)

        for candidate_key in key_candidates:
            test_decrypt = decrypt(encrypted, candidate_key)
            print(f"Key '{candidate_key}': {test_decrypt}")

    print(f"\nActual key was: {key}")

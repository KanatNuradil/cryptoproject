"""
Caesar Cipher with Frequency Analysis Breaker

This module implements the Caesar cipher encryption/decryption algorithm
along with a frequency analysis-based cryptanalysis tool for breaking
the cipher automatically.

The Caesar cipher is a substitution cipher where each letter in the plaintext
is shifted by a fixed number of positions in the alphabet.
"""

import string
from collections import Counter
from typing import Dict, List, Tuple

# English letter frequencies (approximate, based on large corpora)
ENGLISH_FREQUENCIES = {
    'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7, 'S': 6.3, 'H': 6.1,
    'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8, 'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2,
    'G': 2.0, 'Y': 2.0, 'P': 1.9, 'B': 1.5, 'V': 1.0, 'K': 0.8, 'J': 0.2, 'X': 0.2,
    'Q': 0.1, 'Z': 0.1
}


def encrypt(plaintext: str, shift: int) -> str:
    """
    Encrypt plaintext using Caesar cipher with given shift.

    Args:
        plaintext: Text to encrypt
        shift: Number of positions to shift (0-25)

    Returns:
        Encrypted ciphertext
    """
    if not isinstance(shift, int) or not (0 <= shift <= 25):
        raise ValueError("Shift must be an integer between 0 and 25")

    result = []
    for char in plaintext.upper():
        if char.isalpha():
            # Shift within alphabet bounds
            shifted = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            result.append(shifted)
        else:
            # Keep non-alphabetic characters unchanged
            result.append(char)

    return ''.join(result)


def decrypt(ciphertext: str, shift: int) -> str:
    """
    Decrypt ciphertext using Caesar cipher with given shift.

    Args:
        ciphertext: Text to decrypt
        shift: Number of positions to unshift (0-25)

    Returns:
        Decrypted plaintext
    """
    # Decryption is encryption with negative shift
    return encrypt(ciphertext, -shift % 26)


def _calculate_frequencies(text: str) -> Dict[str, float]:
    """
    Calculate letter frequencies in text (case-insensitive).

    Args:
        text: Input text

    Returns:
        Dictionary mapping letters to frequencies (percentages)
    """
    # Count only alphabetic characters
    letters = [char.upper() for char in text if char.isalpha()]
    if not letters:
        return {}

    total_letters = len(letters)
    counts = Counter(letters)

    return {letter: (count / total_letters) * 100 for letter, count in counts.items()}


def _chi_squared_distance(observed_freq: Dict[str, float], expected_freq: Dict[str, float]) -> float:
    """
    Calculate chi-squared distance between observed and expected frequencies.

    Args:
        observed_freq: Observed letter frequencies
        expected_freq: Expected letter frequencies

    Returns:
        Chi-squared distance score (lower = better match)
    """
    score = 0.0
    for letter in string.ascii_uppercase:
        observed = observed_freq.get(letter, 0)
        expected = expected_freq.get(letter, 0)
        if expected > 0:  # Avoid division by zero
            score += ((observed - expected) ** 2) / expected
    return score


def frequency_analysis(ciphertext: str, num_candidates: int = 5) -> List[Tuple[int, str, float]]:
    """
    Attempt to break Caesar cipher using frequency analysis.

    This function tries all possible shifts (0-25) and ranks them by how well
    their letter frequencies match English language patterns.

    Args:
        ciphertext: Encrypted text to analyze
        num_candidates: Number of best candidates to return

    Returns:
        List of tuples: (shift, decrypted_text, score)
        Lower score = better match to English frequencies
    """
    candidates = []

    for shift in range(26):
        decrypted = decrypt(ciphertext, shift)
        frequencies = _calculate_frequencies(decrypted)
        score = _chi_squared_distance(frequencies, ENGLISH_FREQUENCIES)
        candidates.append((shift, decrypted, score))

    # Sort by score (best matches first)
    candidates.sort(key=lambda x: x[2])

    return candidates[:num_candidates]


def brute_force_attack(ciphertext: str) -> List[Tuple[int, str]]:
    """
    Try all possible Caesar cipher shifts.

    Args:
        ciphertext: Text to decrypt with all possible shifts

    Returns:
        List of tuples: (shift, decrypted_text)
    """
    results = []
    for shift in range(26):
        decrypted = decrypt(ciphertext, shift)
        results.append((shift, decrypted))
    return results


def detect_caesar_cipher(text: str) -> bool:
    """
    Simple heuristic to detect if text might be Caesar cipher encrypted.

    This is a basic check that looks for patterns typical of substitution ciphers.

    Args:
        text: Text to analyze

    Returns:
        True if text might be Caesar cipher encrypted
    """
    if not text:
        return False

    # Count alphabetic vs non-alphabetic characters
    alpha_count = sum(1 for char in text if char.isalpha())
    total_count = len(text)

    if alpha_count / total_count < 0.5:  # Less than 50% letters
        return False

    # Check for unusual patterns (very simple heuristic)
    # In English text, 'E' is most common, but in random substitution,
    # letter frequencies are more uniform

    frequencies = _calculate_frequencies(text)
    if not frequencies:
        return False

    # Check if the most frequent letter is not 'E' (suggests encryption)
    most_frequent = max(frequencies.items(), key=lambda x: x[1])[0]
    return most_frequent != 'E'


# Example usage and testing
if __name__ == "__main__":
    # Example encryption/decryption
    plaintext = "HELLO WORLD"
    shift = 3

    encrypted = encrypt(plaintext, shift)
    decrypted = decrypt(encrypted, shift)

    print(f"Plaintext: {plaintext}")
    print(f"Encrypted (shift {shift}): {encrypted}")
    print(f"Decrypted: {decrypted}")
    print()

    # Frequency analysis attack
    print("Attempting to break the cipher with frequency analysis:")
    candidates = frequency_analysis(encrypted, 3)

    for shift_candidate, text, score in candidates:
        print(f"Shift {shift_candidate}: {text} (score: {score:.2f})")

    print()
    print("Correct shift is likely the one with lowest score (best English match)")

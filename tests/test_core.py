# tests/test_core.py

import pytest
from secure_messaging.crypto import (
    generate_user_secrets,
    derive_message_key,
    encrypt_message,
    decrypt_message,
    b64decode,
)

# -------------------------------
# Test: Encryption and Decryption
# -------------------------------
def test_encryption_decryption():
    """
    Test that a message encrypted for a recipient can be decrypted correctly.
    This ensures end-to-end encryption works as expected.
    """

    # Generate key pairs for sender and recipient
    sender_secrets, sender_public = generate_user_secrets()
    recipient_secrets, recipient_public = generate_user_secrets()

    # Decode recipient's public key from base64 to raw bytes
    recipient_public_bytes = b64decode(recipient_public["x25519"])

    # Derive shared AES and HMAC keys using X25519 ECDH
    aes_key, hmac_key = derive_message_key(sender_secrets.x25519_private, recipient_public_bytes)

    # Original plaintext message
    plaintext = b"Hello, this is a secret message!"

    # Encrypt the message
    encrypted_data = encrypt_message(aes_key, plaintext, hmac_key)

    # Decrypt the message
    decrypted = decrypt_message(aes_key, encrypted_data, hmac_key)

    # Verify that decrypted message matches original
    assert decrypted == plaintext


# -------------------------------
# Test: Key Derivation Produces Different Keys
# -------------------------------
def test_derive_message_key_uniqueness():
    """
    Ensure that different recipients produce different shared keys
    even when the same sender is used.
    """
    sender_secrets, _ = generate_user_secrets()
    recipient1_secrets, recipient1_public = generate_user_secrets()
    recipient2_secrets, recipient2_public = generate_user_secrets()

    key1 = derive_message_key(sender_secrets.x25519_private, b64decode(recipient1_public["x25519"]))
    key2 = derive_message_key(sender_secrets.x25519_private, b64decode(recipient2_public["x25519"]))

    # The AES keys should be different
    assert key1[0] != key2[0]
    # The HMAC keys should be different
    assert key1[1] != key2[1]


# -------------------------------
# Test: Multiple Encryption Rounds
# -------------------------------
def test_multiple_encryption_rounds():
    """
    Encrypt the same message multiple times and ensure ciphertexts differ
    due to different nonces for AES-GCM encryption.
    """
    sender_secrets, _ = generate_user_secrets()
    recipient_secrets, recipient_public = generate_user_secrets()

    recipient_public_bytes = b64decode(recipient_public["x25519"])
    aes_key, hmac_key = derive_message_key(sender_secrets.x25519_private, recipient_public_bytes)

    plaintext = b"Repeated secret message"

    encrypted1 = encrypt_message(aes_key, plaintext, hmac_key)
    encrypted2 = encrypt_message(aes_key, plaintext, hmac_key)

    # Ciphertexts should differ because of random nonces
    assert encrypted1["ciphertext"] != encrypted2["ciphertext"]
    # Decrypting both should yield the same plaintext
    assert decrypt_message(aes_key, encrypted1, hmac_key) == plaintext
    assert decrypt_message(aes_key, encrypted2, hmac_key) == plaintext

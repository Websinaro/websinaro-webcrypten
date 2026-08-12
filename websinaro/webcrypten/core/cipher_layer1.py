"""
cipher_layer1.py
Layer 1 of the Websinaro double-cipher chain: AES-256-GCM.
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from websinaro.webcrypten.utils.exceptions import DecryptionError

NONCE_SIZE = 12  # bytes — standard/recommended size for GCM


def aes_gcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Encrypts plaintext with AES-256-GCM.

    Returns:
        (nonce, ciphertext_with_tag) — nonce is 12 random bytes,
        ciphertext_with_tag has the 16-byte auth tag appended automatically.
    """
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key.")

    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext_with_tag


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes, associated_data: bytes | None = None) -> bytes:
    """
    Decrypts and authenticates AES-256-GCM ciphertext.

    Raises:
        DecryptionError — if the key is wrong, the nonce doesn't match,
        or the ciphertext/tag was tampered with. Never returns partial
        or unauthenticated plaintext.
    """
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key.")

    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
    except InvalidTag:
        raise DecryptionError("Layer 1 (AES-GCM) authentication failed — wrong key or tampered data.")

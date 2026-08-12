"""
cipher_layer2.py
Layer 2 of the Websinaro double-cipher chain: ChaCha20-Poly1305.
Runs AFTER layer 1 (AES-GCM) — encrypts the layer-1 output.
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from websinaro.webcrypten.utils.exceptions import DecryptionError

NONCE_SIZE = 12  # bytes — ChaCha20-Poly1305 also uses a 12-byte nonce


def chacha20_encrypt(key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Encrypts plaintext with ChaCha20-Poly1305.

    Returns:
        (nonce, ciphertext_with_tag) — nonce is 12 random bytes,
        ciphertext_with_tag has the 16-byte Poly1305 tag appended automatically.
    """
    if len(key) != 32:
        raise ValueError("ChaCha20-Poly1305 requires a 32-byte key.")

    nonce = os.urandom(NONCE_SIZE)
    chacha = ChaCha20Poly1305(key)
    ciphertext_with_tag = chacha.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext_with_tag


def chacha20_decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes, associated_data: bytes | None = None) -> bytes:
    """
    Decrypts and authenticates ChaCha20-Poly1305 ciphertext.

    Raises:
        DecryptionError — if the key is wrong, the nonce doesn't match,
        or the ciphertext/tag was tampered with.
    """
    if len(key) != 32:
        raise ValueError("ChaCha20-Poly1305 requires a 32-byte key.")

    chacha = ChaCha20Poly1305(key)
    try:
        return chacha.decrypt(nonce, ciphertext_with_tag, associated_data)
    except InvalidTag:
        raise DecryptionError("Layer 2 (ChaCha20-Poly1305) authentication failed — wrong key or tampered data.")
"""
engine.py
WebCryptPen — orchestrates the full double-cipher chain:
plaintext -> AES-256-GCM (layer 1) -> ChaCha20-Poly1305 (layer 2) -> envelope

Decrypt reverses the order: envelope -> ChaCha20 decrypt -> AES-GCM decrypt -> plaintext
"""

import base64

from websinaro.webcrypten.core.key import Key
from websinaro.webcrypten.core.cipher_layer1 import aes_gcm_encrypt, aes_gcm_decrypt, NONCE_SIZE as L1_NONCE_SIZE
from websinaro.webcrypten.core.cipher_layer2 import chacha20_encrypt, chacha20_decrypt, NONCE_SIZE as L2_NONCE_SIZE
from websinaro.webcrypten.utils.exceptions import DecryptionError

FORMAT_VERSION = 1
VERSION_SIZE = 1


class WebCryptPen:
    """
    Public-facing engine for two-level (double-cipher chained) encryption.

    Usage:
        wcp = WebCryptPen()                          # master key from MASTER_KEY env var
        wcp = WebCryptPen(master_key="...")          # explicit override

        token = wcp.encrypt("hello world")
        plaintext = wcp.decrypt(token)
    """

    def __init__(self, master_key: str | None = None):
        self._key = Key(master_key=master_key)
        self._key1, self._key2 = self._key.derive_keys()

    def encrypt(self, data: bytes | str) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")
        elif not isinstance(data, bytes):
            raise TypeError("encrypt() accepts only str or bytes.")

        # Layer 1: AES-256-GCM
        nonce1, ct1 = aes_gcm_encrypt(self._key1, data)

        # Layer 2: ChaCha20-Poly1305, encrypting layer 1's output
        nonce2, ct2 = chacha20_encrypt(self._key2, ct1)

        envelope = (
            bytes([FORMAT_VERSION])
            + nonce1
            + nonce2
            + ct2
        )
        return base64.b64encode(envelope).decode("ascii")

    def decrypt(self, token: str) -> bytes:
        if not isinstance(token, str):
            raise TypeError("decrypt() accepts a base64-encoded str token.")

        try:
            envelope = base64.b64decode(token, validate=True)
        except Exception:
            raise DecryptionError("Malformed envelope: invalid base64.")

        min_len = VERSION_SIZE + L1_NONCE_SIZE + L2_NONCE_SIZE
        if len(envelope) < min_len:
            raise DecryptionError("Malformed envelope: too short.")

        version = envelope[0]
        if version != FORMAT_VERSION:
            raise DecryptionError(f"Unsupported envelope version: {version}.")

        offset = VERSION_SIZE
        nonce1 = envelope[offset: offset + L1_NONCE_SIZE]
        offset += L1_NONCE_SIZE

        nonce2 = envelope[offset: offset + L2_NONCE_SIZE]
        offset += L2_NONCE_SIZE

        ct2 = envelope[offset:]

        # Reverse layer 2 first (ChaCha20), then layer 1 (AES-GCM)
        ct1 = chacha20_decrypt(self._key2, nonce2, ct2)
        plaintext = aes_gcm_decrypt(self._key1, nonce1, ct1)

        return plaintext
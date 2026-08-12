"""
key.py
Handles loading, validation, and derivation of cryptographic keys
for the Websinaro double-cipher chaining engine.
"""

import os
import re
import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from websinaro.webcrypten.utils.exceptions import (
    SmallKeyError,
    NotStandardFormError,
    KeyLoadError,
)

# Fixed, distinct labels — MUST stay stable across versions or every
# previously-encrypted token becomes undecryptable.
_LAYER1_INFO = b"websinaro-layer1-aes-gcm-v1"
_LAYER2_INFO = b"websinaro-layer2-chacha20-v1"

_KEY_CHARSET_PATTERN = re.compile(r"^[A-Za-z0-9+/=]+$")


class Key:
    """
    Loads a master key (from env var or explicit override), validates its
    strength, and derives two independent 256-bit subkeys via HKDF for
    use in the two encryption layers.
    """

    def __init__(self, master_key: str | None = None):
        self.master_key: str = master_key if master_key is not None else self.load_master_key()
        self.validate_master_key(self.master_key)

    def load_master_key(self) -> str:
        master_key = os.getenv("MASTER_KEY")
        if master_key is None:
            raise KeyLoadError(
                "No key found. Set the MASTER_KEY environment variable, "
                "or pass master_key='...' explicitly to Key() / WebCryptPen()."
            )
        return master_key

    def validate_master_key(self, master_key: str) -> bool:
    if not isinstance(master_key, str):
        raise NotStandardFormError("Master key must be a string.")

    # 32 bytes of raw entropy, base64-encoded, is ~44 chars.
    # Require at least that much so weak/short keys are rejected.
    if len(master_key) < 32:
        raise SmallKeyError(
            "Master key must be at least 32 characters "
            "(use a generated key, e.g. `openssl rand -base64 32`)."
        )

    if not _KEY_CHARSET_PATTERN.match(master_key):
        raise NotStandardFormError(
            "Master key contains invalid characters. "
            "Expected base64 or hex output from a secure key generator."
        )

    return True

    def derive_keys(self) -> tuple[bytes, bytes]:
        """
        Derive two independent 32-byte (256-bit) subkeys from the master key:
        key1 for AES-256-GCM (layer 1), key2 for ChaCha20-Poly1305 (layer 2).
        """
        master_bytes = self.master_key.encode("utf-8")
        key1 = self._derive_key(master_bytes, info_label=_LAYER1_INFO)
        key2 = self._derive_key(master_bytes, info_label=_LAYER2_INFO)

        # Defense in depth: if HKDF ever produced identical keys (should be
        # cryptographically impossible with distinct info labels), fail loud
        # rather than silently running both layers with the same key.
        if hmac.compare_digest(key1, key2):
            raise KeyLoadError("Derived layer keys collided unexpectedly.")

        return key1, key2

    @staticmethod
    def _derive_key(master_key: bytes, info_label: bytes, salt: bytes | None = None) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info_label,
        )
        return hkdf.derive(master_key)
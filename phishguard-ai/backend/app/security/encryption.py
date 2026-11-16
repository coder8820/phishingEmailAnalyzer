"""
PhishGuard AI — Secure Token Encryption Service
Implements symmetric encryption at rest using AES-128-CBC/HMAC-SHA256 (Fernet)
with multi-key rotation support (MultiFernet).
Never exposes or logs plain tokens.
"""

from __future__ import annotations

import base64
import hashlib
import logging
from typing import List, Optional, Union

from cryptography.fernet import Fernet, MultiFernet, InvalidToken

from app.core.config import settings

logger = logging.getLogger(__name__)


class TokenEncryptionError(Exception):
    """Raised when token encryption or decryption fails."""
    pass


class TokenEncryptionService:
    """
    Encrypts and decrypts sensitive OAuth refresh tokens and credentials at rest.
    Supports key rotation via MultiFernet.
    """

    def __init__(self, key_source: Optional[Union[str, List[str]]] = None):
        self._keys: List[bytes] = []
        raw_keys = key_source or settings.EFFECTIVE_TOKEN_ENCRYPTION_KEY

        if isinstance(raw_keys, str):
            key_candidates = [k.strip() for k in raw_keys.split(",") if k.strip()]
        elif isinstance(raw_keys, (list, tuple)):
            key_candidates = [str(k).strip() for k in raw_keys if str(k).strip()]
        else:
            key_candidates = []

        for candidate in key_candidates:
            normalized = self._normalize_to_fernet_key(candidate)
            if normalized:
                self._keys.append(normalized)

        # Fallback for development/testing if no key configured
        if not self._keys:
            if settings.APP_ENV == "production":
                raise TokenEncryptionError(
                    "TOKEN_ENCRYPTION_KEY or ENCRYPTION_KEY must be configured in production."
                )
            fallback = self._normalize_to_fernet_key(settings.APP_SECRET_KEY or "phishguard-dev-default-key")
            self._keys.append(fallback)

        fernets = [Fernet(k) for k in self._keys]
        self._multi_fernet = MultiFernet(fernets)

    @staticmethod
    def _normalize_to_fernet_key(key_input: str) -> bytes:
        """
        Validates or deterministically derives a 32-byte url-safe base64 Fernet key.
        """
        key_bytes = key_input.encode("utf-8")
        try:
            # Check if already a valid Fernet key
            Fernet(key_bytes)
            return key_bytes
        except Exception:
            # Deterministically derive 32-byte Fernet key via SHA-256
            derived = base64.urlsafe_b64encode(hashlib.sha256(key_bytes).digest())
            return derived

    def encrypt(self, plaintext: str) -> bytes:
        """
        Encrypts plaintext string into ciphertext bytes using the primary key.
        Never logs plaintext.
        """
        if not plaintext:
            raise TokenEncryptionError("Cannot encrypt empty token data.")
        try:
            return self._multi_fernet.encrypt(plaintext.encode("utf-8"))
        except Exception as e:
            logger.error("Token encryption failed unexpectedly (sanitized).")
            raise TokenEncryptionError("Token encryption failed.") from None

    def decrypt(self, ciphertext: Union[bytes, str]) -> str:
        """
        Decrypts ciphertext bytes or string using primary or rotation keys.
        Never logs plaintext.
        """
        if not ciphertext:
            raise TokenEncryptionError("Cannot decrypt empty ciphertext.")

        raw_ct = ciphertext.encode("utf-8") if isinstance(ciphertext, str) else ciphertext
        try:
            decrypted_bytes = self._multi_fernet.decrypt(raw_ct)
            return decrypted_bytes.decode("utf-8")
        except InvalidToken:
            logger.error("Failed to decrypt token: invalid token or signature.")
            raise TokenEncryptionError("Failed to decrypt token: invalid token or key.") from None
        except Exception as e:
            logger.error("Token decryption failed unexpectedly (sanitized).")
            raise TokenEncryptionError("Token decryption failed.") from None

    def rotate(self, ciphertext: Union[bytes, str]) -> bytes:
        """
        Re-encrypts ciphertext under the current primary key if it was encrypted
        under an older key in the rotation list.
        """
        if not ciphertext:
            raise TokenEncryptionError("Cannot rotate empty ciphertext.")

        raw_ct = ciphertext.encode("utf-8") if isinstance(ciphertext, str) else ciphertext
        try:
            return self._multi_fernet.rotate(raw_ct)
        except Exception as e:
            logger.error("Token key rotation failed.")
            raise TokenEncryptionError("Token key rotation failed.") from None


# Default singleton instance
_token_encryptor: Optional[TokenEncryptionService] = None


def get_token_encryptor() -> TokenEncryptionService:
    global _token_encryptor
    if _token_encryptor is None:
        _token_encryptor = TokenEncryptionService()
    return _token_encryptor

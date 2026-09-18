"""Authenticated encryption: AES-256-GCM.

Associated data is a required argument, not an optional one. Callers must bind
the message headers they rely on, so an attacker cannot lift a ciphertext out
of one envelope and drop it into another with different headers.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..errors import CryptoError

KEY_SIZE = 32
NONCE_SIZE = 12  # 96 bits: the size GCM is defined for; never reuse per key
TAG_SIZE = 16


def generate_nonce() -> bytes:
    return os.urandom(NONCE_SIZE)


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes) -> tuple[bytes, bytes]:
    """Encrypt and authenticate. Returns (nonce, ciphertext_with_tag).

    A fresh random nonce is generated per call. Keys in QuMail are derived per
    message from a fresh KEM encapsulation, so the birthday bound on random
    96-bit nonces is never approached for a single key.
    """
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    if not associated_data:
        raise ValueError("associated data is mandatory: bind the headers")

    nonce = generate_nonce()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
    """Verify and decrypt.

    Raises `CryptoError` on any failure, with no detail about which check
    failed -- a precise error here would be a padding-oracle equivalent.
    """
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    if len(nonce) != NONCE_SIZE:
        raise CryptoError("message rejected")
    if len(ciphertext) < TAG_SIZE:
        raise CryptoError("message rejected")

    try:
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
    except InvalidTag:
        raise CryptoError("message rejected") from None

"""Key derivation.

Every derived key in QuMail comes through here, and every call must name a
purpose. Passing the same input keying material to two different purposes
therefore yields unrelated keys, which is what stops a key from one context
being replayed into another.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Bound into every derivation so that keys from this protocol version can never
# collide with keys from a future one.
_DOMAIN = b"qumail/v1"


def hkdf(ikm: bytes, *, purpose: bytes, context: bytes = b"", length: int = 32) -> bytes:
    """Derive `length` bytes from `ikm` for a specific `purpose`.

    Args:
        ikm: input keying material (e.g. concatenated KEM shared secrets).
        purpose: a short, unique label. Becomes the HKDF salt.
        context: transcript bytes to bind -- public keys, ciphertexts, sender
            and recipient identity. Becomes the HKDF info.
        length: output size in bytes.
    """
    if not purpose:
        raise ValueError("purpose must not be empty: derivations must be separated")
    if length < 16 or length > 255 * 32:
        raise ValueError("unreasonable key length requested")

    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=_DOMAIN + b"/" + purpose,
        info=context,
    ).derive(ikm)


def digest(*chunks: bytes) -> bytes:
    """SHA-256 over length-prefixed chunks.

    Length prefixing makes the encoding unambiguous: digest(b"ab", b"c") and
    digest(b"a", b"bc") differ, which a plain concatenation could not promise.
    """
    hasher = hashes.Hash(hashes.SHA256())
    for chunk in chunks:
        hasher.update(len(chunk).to_bytes(4, "big"))
        hasher.update(chunk)
    return hasher.finalize()

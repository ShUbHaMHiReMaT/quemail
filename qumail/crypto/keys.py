"""Identities: signing keys, encryption keys, and fingerprints.

A QuMail identity is three keypairs:

    Ed25519          -- signs outgoing messages, proves who sent them
    X25519           -- classical half of the hybrid KEM
    ML-KEM-768       -- post-quantum half of the hybrid KEM

The public halves travel together as a *bundle*. A bundle's fingerprint is a
SHA-256 commitment over all three keys plus the owner's address, so no key can
be swapped inside a bundle without changing the fingerprint users compare.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .. import PROTOCOL_VERSION
from ..errors import CryptoError, EnvelopeError
from .kdf import digest
from .kem import (
    KemPrivateKey,
    KemPublicKey,
    generate_keypair as generate_kem_keypair,
)

ED25519_PUBLIC_SIZE = 32
ED25519_PRIVATE_SIZE = 32
SIGNATURE_SIZE = 64

FINGERPRINT_BYTES = 16  # 128-bit commitment: 32 hex chars, still collision-safe


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str, *, expect: int | None = None) -> bytes:
    """Strict base64 decode with an optional exact-length check."""
    if not isinstance(text, str):
        raise EnvelopeError("expected a base64 string")
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, TypeError) as exc:
        raise EnvelopeError("malformed base64 field") from exc
    if expect is not None and len(raw) != expect:
        raise EnvelopeError("field has unexpected length")
    return raw


@dataclass(frozen=True)
class PublicIdentity:
    """The shareable half of an identity."""

    address: str
    signing_key: bytes
    kem: KemPublicKey

    def __post_init__(self) -> None:
        if len(self.signing_key) != ED25519_PUBLIC_SIZE:
            raise ValueError("bad Ed25519 public key length")
        if not self.address:
            raise ValueError("identity requires an address")

    @property
    def fingerprint(self) -> str:
        """Stable, human-comparable identifier for this bundle."""
        return digest(
            b"qumail-identity-v%d" % PROTOCOL_VERSION,
            self.address.strip().lower().encode("utf-8"),
            self.signing_key,
            self.kem.x25519,
            self.kem.mlkem,
        )[:FINGERPRINT_BYTES].hex()

    def pretty_fingerprint(self) -> str:
        """Grouped for reading aloud when verifying out of band."""
        fp = self.fingerprint
        return " ".join(fp[i : i + 4] for i in range(0, len(fp), 4))

    def to_dict(self) -> dict[str, Any]:
        return {
            "v": PROTOCOL_VERSION,
            "address": self.address,
            "sig_pk": b64e(self.signing_key),
            "x25519_pk": b64e(self.kem.x25519),
            "mlkem_pk": b64e(self.kem.mlkem),
            "fingerprint": self.fingerprint,
        }

    @staticmethod
    def from_dict(data: Any) -> "PublicIdentity":
        if not isinstance(data, dict):
            raise EnvelopeError("identity bundle must be an object")
        if data.get("v") != PROTOCOL_VERSION:
            raise EnvelopeError("unsupported identity bundle version")

        address = data.get("address")
        if not isinstance(address, str) or not address.strip():
            raise EnvelopeError("identity bundle has no address")

        from .kem import MLKEM_PUBLIC_SIZE, X25519_PUBLIC_SIZE

        identity = PublicIdentity(
            address=address.strip(),
            signing_key=b64d(data.get("sig_pk", ""), expect=ED25519_PUBLIC_SIZE),
            kem=KemPublicKey(
                x25519=b64d(data.get("x25519_pk", ""), expect=X25519_PUBLIC_SIZE),
                mlkem=b64d(data.get("mlkem_pk", ""), expect=MLKEM_PUBLIC_SIZE),
            ),
        )

        # If the file claims a fingerprint, it must match what the keys imply.
        # Catches truncation, tampering, and hand-edited bundles.
        claimed = data.get("fingerprint")
        if isinstance(claimed, str) and claimed.strip():
            if claimed.strip().replace(" ", "").lower() != identity.fingerprint:
                raise EnvelopeError("identity bundle fingerprint does not match its keys")
        return identity

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @staticmethod
    def from_json(text: str) -> "PublicIdentity":
        try:
            return PublicIdentity.from_dict(json.loads(text))
        except json.JSONDecodeError as exc:
            raise EnvelopeError("identity bundle is not valid JSON") from exc

    def verify(self, message: bytes, signature: bytes) -> None:
        """Raise `CryptoError` unless `signature` is this identity's."""
        if len(signature) != SIGNATURE_SIZE:
            raise CryptoError("message rejected")
        try:
            Ed25519PublicKey.from_public_bytes(self.signing_key).verify(
                signature, message
            )
        except InvalidSignature:
            raise CryptoError("message rejected") from None


@dataclass(frozen=True)
class PrivateIdentity:
    """A full identity. Only ever stored via `keystore`, never in the clear."""

    address: str
    signing_key: bytes
    kem: KemPrivateKey
    public: PublicIdentity

    @property
    def fingerprint(self) -> str:
        return self.public.fingerprint

    def sign(self, message: bytes) -> bytes:
        return Ed25519PrivateKey.from_private_bytes(self.signing_key).sign(message)


def generate_identity(address: str) -> PrivateIdentity:
    """Create a brand new identity for `address`."""
    address = address.strip()
    if not address:
        raise ValueError("identity requires an address")

    signing = Ed25519PrivateKey.generate()
    signing_raw = signing.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    signing_pub = signing.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    kem_public, kem_private = generate_kem_keypair()

    return PrivateIdentity(
        address=address,
        signing_key=signing_raw,
        kem=kem_private,
        public=PublicIdentity(
            address=address, signing_key=signing_pub, kem=kem_public
        ),
    )

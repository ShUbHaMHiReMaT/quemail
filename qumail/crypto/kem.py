"""Hybrid key encapsulation: X25519 + ML-KEM-768.

Two independent KEMs run for every message and their shared secrets are fed
together into one HKDF. The derived key stays secret unless *both* are broken:

  * X25519 protects against a flaw in the newer lattice scheme or its
    implementation.
  * ML-KEM-768 (FIPS 203) protects against an adversary who records traffic
    today and runs Shor's algorithm on it later.

This is the construction NIST and the IETF recommend for the migration
period, and it is strictly stronger than either half alone.

The derived key is bound to a transcript covering both ephemeral and static
public keys plus the caller's context, so a key agreed for one message and one
pair of identities cannot be transplanted to another.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from kyber_py.ml_kem import ML_KEM_768

from ..errors import CryptoError
from .kdf import digest, hkdf

X25519_PUBLIC_SIZE = 32
X25519_PRIVATE_SIZE = 32
MLKEM_PUBLIC_SIZE = 1184  # ML-KEM-768 encapsulation key
MLKEM_PRIVATE_SIZE = 2400  # ML-KEM-768 decapsulation key
MLKEM_CIPHERTEXT_SIZE = 1088

SHARED_KEY_SIZE = 32

_KEM_PURPOSE = b"hybrid-kem/x25519+mlkem768"


@dataclass(frozen=True)
class KemPublicKey:
    """The recipient's long-term encryption key: one half per KEM."""

    x25519: bytes
    mlkem: bytes

    def __post_init__(self) -> None:
        if len(self.x25519) != X25519_PUBLIC_SIZE:
            raise ValueError("bad X25519 public key length")
        if len(self.mlkem) != MLKEM_PUBLIC_SIZE:
            raise ValueError("bad ML-KEM-768 encapsulation key length")


@dataclass(frozen=True)
class KemPrivateKey:
    """The matching private halves. Never serialise this unencrypted."""

    x25519: bytes
    mlkem: bytes

    def __post_init__(self) -> None:
        if len(self.x25519) != X25519_PRIVATE_SIZE:
            raise ValueError("bad X25519 private key length")
        if len(self.mlkem) != MLKEM_PRIVATE_SIZE:
            raise ValueError("bad ML-KEM-768 decapsulation key length")


@dataclass(frozen=True)
class KemCiphertext:
    """What travels with the message so the recipient can recover the key."""

    x25519_ephemeral: bytes
    mlkem: bytes

    def __post_init__(self) -> None:
        if len(self.x25519_ephemeral) != X25519_PUBLIC_SIZE:
            raise ValueError("bad X25519 ephemeral key length")
        if len(self.mlkem) != MLKEM_CIPHERTEXT_SIZE:
            raise ValueError("bad ML-KEM-768 ciphertext length")


def generate_keypair() -> tuple[KemPublicKey, KemPrivateKey]:
    """Generate a fresh hybrid encryption keypair."""
    x_priv = X25519PrivateKey.generate()
    x_priv_raw = x_priv.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    x_pub_raw = x_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    mlkem_ek, mlkem_dk = ML_KEM_768.keygen()

    return (
        KemPublicKey(x25519=x_pub_raw, mlkem=bytes(mlkem_ek)),
        KemPrivateKey(x25519=x_priv_raw, mlkem=bytes(mlkem_dk)),
    )


def _transcript(
    public: KemPublicKey, ciphertext: KemCiphertext, context: bytes
) -> bytes:
    """Everything the derived key is bound to."""
    return digest(
        ciphertext.x25519_ephemeral,
        public.x25519,
        ciphertext.mlkem,
        public.mlkem,
        context,
    )


def encapsulate(public: KemPublicKey, context: bytes) -> tuple[KemCiphertext, bytes]:
    """Agree a fresh key with the holder of `public`.

    Returns the ciphertext to transmit and the 32-byte derived key.
    `context` is bound into the derivation and must be reproduced exactly by
    the recipient.
    """
    ephemeral = X25519PrivateKey.generate()
    ephemeral_pub = ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    try:
        classical_secret = ephemeral.exchange(X25519PublicKey.from_public_bytes(public.x25519))
    except ValueError as exc:  # degenerate / low-order recipient key
        raise CryptoError("invalid recipient X25519 key") from exc

    pq_secret, pq_ciphertext = ML_KEM_768.encaps(public.mlkem)

    ciphertext = KemCiphertext(
        x25519_ephemeral=ephemeral_pub, mlkem=bytes(pq_ciphertext)
    )
    key = hkdf(
        bytes(classical_secret) + bytes(pq_secret),
        purpose=_KEM_PURPOSE,
        context=_transcript(public, ciphertext, context),
        length=SHARED_KEY_SIZE,
    )
    return ciphertext, key


def decapsulate(
    private: KemPrivateKey,
    public: KemPublicKey,
    ciphertext: KemCiphertext,
    context: bytes,
) -> bytes:
    """Recover the key agreed by `encapsulate`.

    A wrong or tampered ciphertext does not raise here: ML-KEM performs
    implicit rejection and returns an unpredictable key instead. The mismatch
    surfaces as an AEAD authentication failure, which keeps this function from
    acting as an oracle.
    """
    x_priv = X25519PrivateKey.from_private_bytes(private.x25519)
    try:
        classical_secret = x_priv.exchange(
            X25519PublicKey.from_public_bytes(ciphertext.x25519_ephemeral)
        )
    except ValueError as exc:
        raise CryptoError("message rejected") from exc

    pq_secret = ML_KEM_768.decaps(private.mlkem, ciphertext.mlkem)

    return hkdf(
        bytes(classical_secret) + bytes(pq_secret),
        purpose=_KEM_PURPOSE,
        context=_transcript(public, ciphertext, context),
        length=SHARED_KEY_SIZE,
    )

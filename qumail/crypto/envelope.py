"""The QuMail envelope: the bytes that actually travel over email.

Construction, in order:

1.  A hybrid KEM (X25519 + ML-KEM-768) agrees a fresh 32-byte key, bound to a
    context naming the protocol version, message id, timestamp, subject, and
    both parties' fingerprints.
2.  AES-256-GCM encrypts the body with the canonical header as associated
    data, so no header field can be altered without breaking decryption.
3.  Ed25519 signs the header *and* the ciphertext (encrypt-then-sign), proving
    who sent the message.

The sender's fingerprint is inside the KEM context, which closes the usual gap
in encrypt-then-sign: an attacker who strips the signature and re-signs under
their own identity changes the context, so the key no longer derives and the
body will not decrypt. Authorship is cryptographically bound to the content,
not merely asserted beside it.

Header fields are deliberately minimal. Everything in them is visible to the
mail provider, so the plaintext body -- and only the body -- carries content.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any

from .. import PROTOCOL_VERSION
from ..errors import CryptoError, EnvelopeError
from .aead import NONCE_SIZE, TAG_SIZE, decrypt as aead_decrypt, encrypt as aead_encrypt
from .kem import (
    MLKEM_CIPHERTEXT_SIZE,
    X25519_PUBLIC_SIZE,
    KemCiphertext,
    KemPrivateKey,
    KemPublicKey,
    decapsulate,
    encapsulate,
)
from .keys import SIGNATURE_SIZE, PrivateIdentity, PublicIdentity, b64d, b64e

MESSAGE_ID_BYTES = 16
MESSAGE_ID_RE = re.compile(r"\A[0-9a-f]{32}\Z")

# Ceilings applied before any parsing work, so a hostile message cannot make a
# receiver allocate unbounded memory.
MAX_ENVELOPE_BYTES = 8 * 1024 * 1024
MAX_PLAINTEXT_BYTES = 4 * 1024 * 1024
MAX_SUBJECT_LENGTH = 256
MAX_ADDRESS_LENGTH = 320  # RFC 5321 maximum path length

_CONTEXT_PURPOSE = b"qumail-envelope-v%d" % PROTOCOL_VERSION


def new_message_id() -> str:
    """A random id. Never derived from content, and never attacker-chosen."""
    return os.urandom(MESSAGE_ID_BYTES).hex()


def validate_message_id(value: Any) -> str:
    """Accept only 32 lowercase hex characters.

    This is the single most important input check in the receiver: the id ends
    up in an output filename, and anything looser would allow a remote sender
    to steer writes with `../` or a drive prefix.
    """
    if not isinstance(value, str) or not MESSAGE_ID_RE.match(value):
        raise EnvelopeError("message id is not a 32-character hex string")
    return value


@dataclass(frozen=True)
class EnvelopeHeader:
    """Public, authenticated metadata."""

    version: int
    message_id: str
    timestamp: int
    sender_fingerprint: str
    recipient_fingerprint: str
    subject: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "v": self.version,
            "id": self.message_id,
            "ts": self.timestamp,
            "from_fp": self.sender_fingerprint,
            "to_fp": self.recipient_fingerprint,
            "subject": self.subject,
        }

    def canonical(self) -> bytes:
        """Byte-exact, order-independent encoding used for AAD and signing."""
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")

    @staticmethod
    def from_dict(data: Any) -> "EnvelopeHeader":
        if not isinstance(data, dict):
            raise EnvelopeError("envelope header must be an object")
        if data.get("v") != PROTOCOL_VERSION:
            raise EnvelopeError("unsupported envelope version")

        timestamp = data.get("ts")
        if not isinstance(timestamp, int) or isinstance(timestamp, bool):
            raise EnvelopeError("envelope timestamp must be an integer")
        if not 0 < timestamp < 2 ** 63:
            raise EnvelopeError("envelope timestamp is out of range")

        subject = data.get("subject", "")
        if not isinstance(subject, str) or len(subject) > MAX_SUBJECT_LENGTH:
            raise EnvelopeError("envelope subject is missing or too long")

        return EnvelopeHeader(
            version=PROTOCOL_VERSION,
            message_id=validate_message_id(data.get("id")),
            timestamp=timestamp,
            sender_fingerprint=_validate_fingerprint(data.get("from_fp")),
            recipient_fingerprint=_validate_fingerprint(data.get("to_fp")),
            subject=subject,
        )


def _validate_fingerprint(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value):
        raise EnvelopeError("fingerprint is not a 32-character hex string")
    return value


@dataclass(frozen=True)
class Envelope:
    """A complete sealed message."""

    header: EnvelopeHeader
    kem_ciphertext: KemCiphertext
    nonce: bytes
    ciphertext: bytes
    signature: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "hdr": self.header.to_dict(),
            "kem": {
                "x25519": b64e(self.kem_ciphertext.x25519_ephemeral),
                "mlkem": b64e(self.kem_ciphertext.mlkem),
            },
            "nonce": b64e(self.nonce),
            "ct": b64e(self.ciphertext),
            "sig": b64e(self.signature),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @staticmethod
    def from_json(text: str) -> "Envelope":
        if len(text) > MAX_ENVELOPE_BYTES:
            raise EnvelopeError("envelope exceeds the maximum accepted size")
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise EnvelopeError("envelope is not valid JSON") from exc
        if not isinstance(data, dict):
            raise EnvelopeError("envelope must be a JSON object")

        kem = data.get("kem")
        if not isinstance(kem, dict):
            raise EnvelopeError("envelope is missing its KEM ciphertext")

        ciphertext = b64d(data.get("ct", ""))
        if len(ciphertext) < TAG_SIZE:
            raise EnvelopeError("envelope ciphertext is too short")
        if len(ciphertext) > MAX_PLAINTEXT_BYTES + TAG_SIZE:
            raise EnvelopeError("envelope ciphertext exceeds the maximum accepted size")

        return Envelope(
            header=EnvelopeHeader.from_dict(data.get("hdr")),
            kem_ciphertext=KemCiphertext(
                x25519_ephemeral=b64d(kem.get("x25519", ""), expect=X25519_PUBLIC_SIZE),
                mlkem=b64d(kem.get("mlkem", ""), expect=MLKEM_CIPHERTEXT_SIZE),
            ),
            nonce=b64d(data.get("nonce", ""), expect=NONCE_SIZE),
            ciphertext=ciphertext,
            signature=b64d(data.get("sig", ""), expect=SIGNATURE_SIZE),
        )


def _kem_context(header: EnvelopeHeader) -> bytes:
    """Identity- and message-binding context for the KEM derivation."""
    return _CONTEXT_PURPOSE + b"|" + header.canonical()


def _signed_bytes(header: EnvelopeHeader, kem: KemCiphertext, nonce: bytes,
                  ciphertext: bytes) -> bytes:
    """Everything the sender's signature covers."""
    return b"|".join(
        (
            b"qumail-signature-v%d" % PROTOCOL_VERSION,
            header.canonical(),
            kem.x25519_ephemeral,
            kem.mlkem,
            nonce,
            ciphertext,
        )
    )


def seal(
    sender: PrivateIdentity,
    recipient: PublicIdentity,
    plaintext: bytes,
    *,
    subject: str = "",
    timestamp: int | None = None,
) -> Envelope:
    """Encrypt and sign `plaintext` from `sender` to `recipient`."""
    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise EnvelopeError(
            "message body exceeds the %d byte limit" % MAX_PLAINTEXT_BYTES
        )
    if len(subject) > MAX_SUBJECT_LENGTH:
        raise EnvelopeError("subject exceeds the maximum length")

    header = EnvelopeHeader(
        version=PROTOCOL_VERSION,
        message_id=new_message_id(),
        timestamp=int(time.time()) if timestamp is None else int(timestamp),
        sender_fingerprint=sender.fingerprint,
        recipient_fingerprint=recipient.fingerprint,
        subject=subject,
    )

    kem_ciphertext, key = encapsulate(recipient.kem, _kem_context(header))
    nonce, ciphertext = aead_encrypt(key, plaintext, header.canonical())
    signature = sender.sign(_signed_bytes(header, kem_ciphertext, nonce, ciphertext))

    return Envelope(
        header=header,
        kem_ciphertext=kem_ciphertext,
        nonce=nonce,
        ciphertext=ciphertext,
        signature=signature,
    )


def open_envelope(
    envelope: Envelope,
    recipient_private: KemPrivateKey,
    recipient_public: KemPublicKey,
    sender: PublicIdentity,
) -> bytes:
    """Verify `envelope` came from `sender` and decrypt it.

    Order matters: the signature is checked before any key material is touched,
    so an unauthenticated sender cannot make us perform decapsulation work.

    Raises `CryptoError` if the signature, the sender's identity, or the
    ciphertext fails to verify.
    """
    if sender.fingerprint != envelope.header.sender_fingerprint:
        raise CryptoError("message rejected")

    sender.verify(
        _signed_bytes(
            envelope.header,
            envelope.kem_ciphertext,
            envelope.nonce,
            envelope.ciphertext,
        ),
        envelope.signature,
    )

    key = decapsulate(
        recipient_private,
        recipient_public,
        envelope.kem_ciphertext,
        _kem_context(envelope.header),
    )
    return aead_decrypt(
        key, envelope.nonce, envelope.ciphertext, envelope.header.canonical()
    )

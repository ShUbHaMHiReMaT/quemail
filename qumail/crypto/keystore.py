"""Passphrase-encrypted storage for a private identity.

Private keys never touch the disk in the clear. The file holds an AES-256-GCM
ciphertext under a key derived from the operator's passphrase with scrypt,
whose memory-hard cost makes offline guessing expensive even if the file is
stolen. The public metadata stored alongside is authenticated as associated
data, so an attacker cannot swap the address or fingerprint on a file they
cannot decrypt.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .. import PROTOCOL_VERSION
from ..errors import CryptoError, KeystoreError
from ..fsutil import atomic_write_json, is_world_readable, read_json
from ..logging_setup import get_logger
from .aead import KEY_SIZE, decrypt, encrypt
from .kem import (
    MLKEM_PRIVATE_SIZE,
    X25519_PRIVATE_SIZE,
    KemPrivateKey,
    KemPublicKey,
    MLKEM_PUBLIC_SIZE,
    X25519_PUBLIC_SIZE,
)
from .keys import (
    ED25519_PRIVATE_SIZE,
    ED25519_PUBLIC_SIZE,
    PrivateIdentity,
    PublicIdentity,
    b64d,
    b64e,
)

log = get_logger(__name__)

# scrypt parameters. n=2**16 with r=8 costs ~64 MiB and a fraction of a second
# per attempt, which is tolerable for an operator unlocking a daemon and
# punishing for an attacker running a wordlist. Stored in the file so that
# raising them later does not orphan existing keystores.
SCRYPT_N = 2 ** 16
SCRYPT_R = 8
SCRYPT_P = 1
SALT_SIZE = 16

MIN_PASSPHRASE_LENGTH = 12

# A corrupt or hostile file must not be able to make us allocate 64 GiB.
MAX_SCRYPT_N = 2 ** 20
MAX_KEYSTORE_BYTES = 64 * 1024


def _derive(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    if n > MAX_SCRYPT_N or n < 2 ** 14 or n & (n - 1):
        raise KeystoreError("keystore declares unacceptable scrypt cost parameters")
    if not 1 <= r <= 32 or not 1 <= p <= 16:
        raise KeystoreError("keystore declares unacceptable scrypt cost parameters")
    return Scrypt(salt=salt, length=KEY_SIZE, n=n, r=r, p=p).derive(
        passphrase.encode("utf-8")
    )


def _associated_data(header: dict[str, Any]) -> bytes:
    """Canonical bytes of the plaintext header, bound into the AEAD."""
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


def validate_passphrase(passphrase: str) -> None:
    """Reject passphrases too weak to be worth the scrypt cost."""
    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise KeystoreError(
            "passphrase must be at least %d characters" % MIN_PASSPHRASE_LENGTH
        )


def save(path: Path, identity: PrivateIdentity, passphrase: str, *, overwrite: bool = False) -> None:
    """Encrypt `identity` to `path`.

    Refuses to clobber an existing keystore unless `overwrite` is set --
    losing a private key to a stray `keygen` is unrecoverable.
    """
    validate_passphrase(passphrase)
    if path.exists() and not overwrite:
        raise KeystoreError(
            "keystore already exists at %s; refusing to overwrite" % path
        )

    salt = os.urandom(SALT_SIZE)
    header = {
        "v": PROTOCOL_VERSION,
        "address": identity.address,
        "fingerprint": identity.fingerprint,
        "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
                "salt": b64e(salt)},
    }

    secret = json.dumps(
        {
            "sig_sk": b64e(identity.signing_key),
            "x25519_sk": b64e(identity.kem.x25519),
            "mlkem_sk": b64e(identity.kem.mlkem),
            "sig_pk": b64e(identity.public.signing_key),
            "x25519_pk": b64e(identity.public.kem.x25519),
            "mlkem_pk": b64e(identity.public.kem.mlkem),
        },
        sort_keys=True,
    ).encode("utf-8")

    key = _derive(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    nonce, ciphertext = encrypt(key, secret, _associated_data(header))

    atomic_write_json(
        path, dict(header, nonce=b64e(nonce), ct=b64e(ciphertext)), private=True
    )
    log.info("keystore written to %s", path)


def load(path: Path, passphrase: str) -> PrivateIdentity:
    """Decrypt the identity stored at `path`."""
    if not path.exists():
        raise KeystoreError(
            "no keystore at %s -- run 'qumail keygen' first" % path
        )
    if path.stat().st_size > MAX_KEYSTORE_BYTES:
        raise KeystoreError("keystore file is implausibly large; refusing to parse")
    if is_world_readable(path):
        # Do not silently continue: the key may already be compromised.
        raise KeystoreError(
            "keystore at %s is readable by other users; fix with 'chmod 600 %s' "
            "and rotate the identity if it may have been exposed" % (path, path)
        )

    try:
        data = read_json(path)
    except (json.JSONDecodeError, OSError) as exc:
        raise KeystoreError("keystore is unreadable or corrupt") from exc
    if not isinstance(data, dict) or data.get("v") != PROTOCOL_VERSION:
        raise KeystoreError("unsupported keystore version")

    kdf = data.get("kdf")
    if not isinstance(kdf, dict) or kdf.get("name") != "scrypt":
        raise KeystoreError("keystore uses an unknown key derivation function")

    header = {
        "v": data["v"],
        "address": data.get("address"),
        "fingerprint": data.get("fingerprint"),
        "kdf": kdf,
    }

    try:
        key = _derive(
            passphrase,
            b64d(kdf.get("salt", "")),
            int(kdf.get("n", 0)),
            int(kdf.get("r", 0)),
            int(kdf.get("p", 0)),
        )
    except (TypeError, ValueError) as exc:
        raise KeystoreError("keystore header is malformed") from exc

    try:
        plaintext = decrypt(
            key,
            b64d(data.get("nonce", "")),
            b64d(data.get("ct", "")),
            _associated_data(header),
        )
    except CryptoError as exc:
        # Wrong passphrase and tampered file are indistinguishable by design.
        raise KeystoreError(
            "could not unlock keystore: wrong passphrase or the file has been altered"
        ) from exc

    try:
        secret = json.loads(plaintext)
        public = PublicIdentity(
            address=str(header["address"]),
            signing_key=b64d(secret["sig_pk"], expect=ED25519_PUBLIC_SIZE),
            kem=KemPublicKey(
                x25519=b64d(secret["x25519_pk"], expect=X25519_PUBLIC_SIZE),
                mlkem=b64d(secret["mlkem_pk"], expect=MLKEM_PUBLIC_SIZE),
            ),
        )
        identity = PrivateIdentity(
            address=public.address,
            signing_key=b64d(secret["sig_sk"], expect=ED25519_PRIVATE_SIZE),
            kem=KemPrivateKey(
                x25519=b64d(secret["x25519_sk"], expect=X25519_PRIVATE_SIZE),
                mlkem=b64d(secret["mlkem_sk"], expect=MLKEM_PRIVATE_SIZE),
            ),
            public=public,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise KeystoreError("keystore contents are malformed") from exc

    # The header is authenticated, but a fingerprint that disagrees with the
    # keys would still mean the file was built wrong. Fail rather than serve
    # an identity under a name that is not really its own.
    if header["fingerprint"] != identity.fingerprint:
        raise KeystoreError("keystore fingerprint does not match the stored keys")

    return identity

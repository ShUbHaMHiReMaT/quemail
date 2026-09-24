"""Authentication for the web inbox.

The inbox shows decrypted mail, so reaching it must require a password even
when the service is only bound to localhost -- and especially when it is not.

Three mechanisms:

    * the password is stored only as an scrypt hash, never in the clear
    * sessions are HMAC-signed bearer tokens with an expiry, held in a cookie
      that JavaScript cannot read
    * CSRF tokens are bound to the session, so another site cannot make your
      browser send mail on your behalf
"""

from __future__ import annotations

import base64
import hmac
import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from ..errors import ConfigError
from ..logging_setup import get_logger

log = get_logger(__name__)

# Same cost as the keystore: ~64 MiB and a fraction of a second per attempt.
SCRYPT_N = 2 ** 16
SCRYPT_R = 8
SCRYPT_P = 1
SALT_SIZE = 16
HASH_SIZE = 32

MIN_PASSWORD_LENGTH = 12
SESSION_LIFETIME = 12 * 3600
SESSION_COOKIE = "qumail_session"

# Login throttling. Deliberately strict: there is one account and a human
# typing it, so a handful of failures a minute is plenty.
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


# ---------------------------------------------------------------- password


def hash_password(password: str) -> str:
    """Return a self-describing scrypt hash, safe to put in an env var."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ConfigError(
            "web password must be at least %d characters" % MIN_PASSWORD_LENGTH
        )
    salt = os.urandom(SALT_SIZE)
    digest = Scrypt(salt=salt, length=HASH_SIZE, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(
        password.encode("utf-8")
    )
    return "scrypt$%d$%d$%d$%s$%s" % (
        SCRYPT_N, SCRYPT_R, SCRYPT_P, _b64e(salt), _b64e(digest)
    )


def verify_password(password: str, encoded: str) -> bool:
    """Check a password against a stored hash, in constant time."""
    try:
        scheme, n_s, r_s, p_s, salt_s, digest_s = encoded.strip().split("$")
        if scheme != "scrypt":
            return False
        n, r, p = int(n_s), int(r_s), int(p_s)
        # Bound the work a malformed or hostile hash string can demand.
        if n > 2 ** 20 or n < 2 ** 14 or n & (n - 1) or not 1 <= r <= 32 or not 1 <= p <= 16:
            return False
        salt, expected = _b64d(salt_s), _b64d(digest_s)
    except (ValueError, TypeError):
        return False

    try:
        derived = Scrypt(
            salt=salt, length=len(expected), n=n, r=r, p=p
        ).derive(password.encode("utf-8"))
    except Exception:
        return False
    return bytes_eq(derived, expected)


# ---------------------------------------------------------------- sessions


@dataclass
class LoginThrottle:
    """Per-process failed-login counter."""

    attempts: Dict[str, Tuple[int, float]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def locked_for(self, client: str) -> int:
        """Seconds remaining in a lockout, or 0."""
        with self._lock:
            count, last = self.attempts.get(client, (0, 0.0))
            if count < MAX_ATTEMPTS:
                return 0
            remaining = int(LOCKOUT_SECONDS - (time.time() - last))
            if remaining <= 0:
                self.attempts.pop(client, None)
                return 0
            return remaining

    def record_failure(self, client: str) -> None:
        with self._lock:
            count, _ = self.attempts.get(client, (0, 0.0))
            self.attempts[client] = (count + 1, time.time())

    def record_success(self, client: str) -> None:
        with self._lock:
            self.attempts.pop(client, None)


class SessionManager:
    """Issues and validates signed session tokens.

    Tokens are stateless: the server keeps no session table, so a restart
    invalidates everything only if the secret changes. Supplying a stable
    secret keeps people logged in across deploys.
    """

    def __init__(self, secret: Optional[bytes] = None, *, secure_cookies: bool = True) -> None:
        self.secret = secret or os.urandom(32)
        self.secure_cookies = secure_cookies
        self.throttle = LoginThrottle()

    def _sign(self, payload: bytes) -> bytes:
        return hmac.new(self.secret, payload, "sha256").digest()

    def issue(self) -> str:
        payload = json.dumps(
            {"exp": int(time.time()) + SESSION_LIFETIME, "jti": _b64e(os.urandom(12))},
            separators=(",", ":"),
        ).encode("utf-8")
        return "%s.%s" % (_b64e(payload), _b64e(self._sign(payload)))

    def validate(self, token: Optional[str]) -> bool:
        if not token or token.count(".") != 1:
            return False
        payload_s, signature_s = token.split(".")
        try:
            payload, signature = _b64d(payload_s), _b64d(signature_s)
        except (ValueError, TypeError):
            return False
        # Signature first: never parse a payload we have not authenticated.
        if not bytes_eq(self._sign(payload), signature):
            return False
        try:
            claims = json.loads(payload)
            return int(claims["exp"]) > time.time()
        except (ValueError, KeyError, TypeError):
            return False

    def csrf_token(self, session_token: str) -> str:
        """A CSRF token derived from the session, so it cannot be transplanted."""
        return _b64e(hmac.new(self.secret, b"csrf|" + session_token.encode(), "sha256").digest())

    def check_csrf(self, session_token: str, supplied: Optional[str]) -> bool:
        if not supplied:
            return False
        return bytes_eq(
            self.csrf_token(session_token).encode("ascii"), supplied.encode("ascii", "replace")
        )

    def cookie_header(self, token: str) -> str:
        parts = [
            "%s=%s" % (SESSION_COOKIE, token),
            "Path=/",
            "HttpOnly",
            "SameSite=Strict",
            "Max-Age=%d" % SESSION_LIFETIME,
        ]
        if self.secure_cookies:
            parts.append("Secure")
        return "; ".join(parts)

    def clear_cookie_header(self) -> str:
        return "%s=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0" % SESSION_COOKIE

"""Configuration: environment first, fail closed.

There are no built-in credentials and no fallback accounts. Anything secret
must be supplied by the operator through the environment or a `.env` file that
is never committed. A missing or malformed setting stops the process rather
than silently defaulting to something less safe.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .errors import ConfigError
from .fsutil import is_world_readable

DEFAULT_HOME = Path.home() / ".qumail"

# Values that must never be accepted silently from a config file.
_TRUTHY = {"1", "true", "yes", "on"}
_FALSY = {"0", "false", "no", "off"}


def load_dotenv(path: Path) -> None:
    """Load KEY=VALUE lines from `path` into the environment.

    Real environment variables always win, so a container's injected secrets
    are never overridden by a stale file left in the image.
    """
    if not path.exists():
        return
    if is_world_readable(path):
        raise ConfigError(
            "%s is readable by other users; run 'chmod 600 %s'" % (path, path)
        )

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value


def _get(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.environ.get(name)
    if value is None:
        return default
    value = value.strip()
    return value if value else default


def _require(name: str) -> str:
    value = _get(name)
    if not value:
        raise ConfigError(
            "%s is not set. Copy .env.example to .env and fill it in, or export "
            "the variable." % name
        )
    return value


def _get_int(name: str, default: int, *, minimum: int = 0, maximum: int = 2 ** 31) -> int:
    raw = _get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError("%s must be an integer, got %r" % (name, raw)) from None
    if not minimum <= value <= maximum:
        raise ConfigError(
            "%s must be between %d and %d, got %d" % (name, minimum, maximum, value)
        )
    return value


def _get_bool(name: str, default: bool) -> bool:
    raw = _get(name)
    if raw is None:
        return default
    lowered = raw.lower()
    if lowered in _TRUTHY:
        return True
    if lowered in _FALSY:
        return False
    raise ConfigError("%s must be true or false, got %r" % (name, raw))


def _get_path(name: str, default: Path) -> Path:
    raw = _get(name)
    return Path(raw).expanduser().resolve() if raw else default


@dataclass(frozen=True)
class SmtpConfig:
    host: str
    port: int
    username: str
    password: str
    security: str  # "starttls" or "ssl"
    from_address: str
    timeout: int


@dataclass(frozen=True)
class ImapConfig:
    host: str
    port: int
    username: str
    password: str
    mailbox: str
    timeout: int


@dataclass(frozen=True)
class Policy:
    """Receiver-side rules. The defaults are the strict ones."""

    poll_interval: int = 30
    max_message_bytes: int = 1024 * 1024
    max_message_age: int = 7 * 24 * 3600
    max_clock_skew: int = 300
    max_messages_per_poll: int = 50


@dataclass(frozen=True)
class Config:
    home: Path
    keystore_path: Path
    contacts_path: Path
    state_dir: Path
    output_dir: Path
    policy: Policy = field(default_factory=Policy)
    _smtp: Optional[SmtpConfig] = None
    _imap: Optional[ImapConfig] = None
    log_level: str = "INFO"
    log_format: str = "text"

    @property
    def smtp(self) -> SmtpConfig:
        """SMTP settings, resolved on first use so `keygen` needs no mail config."""
        if self._smtp is None:
            raise ConfigError("SMTP is not configured")
        return self._smtp

    @property
    def imap(self) -> ImapConfig:
        if self._imap is None:
            raise ConfigError("IMAP is not configured")
        return self._imap


def load_smtp() -> SmtpConfig:
    security = (_get("QUMAIL_SMTP_SECURITY", "starttls") or "starttls").lower()
    if security not in ("starttls", "ssl"):
        raise ConfigError(
            "QUMAIL_SMTP_SECURITY must be 'starttls' or 'ssl'. Unencrypted SMTP "
            "is not supported."
        )
    return SmtpConfig(
        host=_require("QUMAIL_SMTP_HOST"),
        port=_get_int("QUMAIL_SMTP_PORT", 587, minimum=1, maximum=65535),
        username=_require("QUMAIL_SMTP_USERNAME"),
        password=_require("QUMAIL_SMTP_PASSWORD"),
        security=security,
        from_address=_get("QUMAIL_FROM_ADDRESS") or _require("QUMAIL_SMTP_USERNAME"),
        timeout=_get_int("QUMAIL_SMTP_TIMEOUT", 30, minimum=5, maximum=300),
    )


def load_imap() -> ImapConfig:
    mailbox = _get("QUMAIL_IMAP_MAILBOX", "INBOX") or "INBOX"
    # The mailbox name is interpolated into an IMAP command; keep it boring.
    if not all(ch.isalnum() or ch in "._-/ " for ch in mailbox):
        raise ConfigError("QUMAIL_IMAP_MAILBOX contains unsupported characters")
    return ImapConfig(
        host=_require("QUMAIL_IMAP_HOST"),
        port=_get_int("QUMAIL_IMAP_PORT", 993, minimum=1, maximum=65535),
        username=_require("QUMAIL_IMAP_USERNAME"),
        password=_require("QUMAIL_IMAP_PASSWORD"),
        mailbox=mailbox,
        timeout=_get_int("QUMAIL_IMAP_TIMEOUT", 60, minimum=5, maximum=600),
    )


def load_config(*, dotenv: Optional[Path] = None, with_smtp: bool = False,
                with_imap: bool = False) -> Config:
    """Build the configuration.

    `with_smtp` / `with_imap` control whether mail credentials are required,
    so local-only commands do not demand a mail account.
    """
    load_dotenv(dotenv if dotenv is not None else Path.cwd() / ".env")

    home = _get_path("QUMAIL_HOME", DEFAULT_HOME)
    policy = Policy(
        poll_interval=_get_int("QUMAIL_POLL_INTERVAL", 30, minimum=5, maximum=3600),
        max_message_bytes=_get_int(
            "QUMAIL_MAX_MESSAGE_BYTES", 1024 * 1024, minimum=1024, maximum=16 * 1024 * 1024
        ),
        max_message_age=_get_int(
            "QUMAIL_MAX_MESSAGE_AGE", 7 * 24 * 3600, minimum=60, maximum=365 * 24 * 3600
        ),
        max_clock_skew=_get_int("QUMAIL_MAX_CLOCK_SKEW", 300, minimum=0, maximum=86400),
        max_messages_per_poll=_get_int(
            "QUMAIL_MAX_MESSAGES_PER_POLL", 50, minimum=1, maximum=500
        ),
    )

    return Config(
        home=home,
        keystore_path=_get_path("QUMAIL_KEYSTORE", home / "keystore.json"),
        contacts_path=_get_path("QUMAIL_CONTACTS", home / "contacts.json"),
        state_dir=_get_path("QUMAIL_STATE_DIR", home / "state"),
        output_dir=_get_path("QUMAIL_OUTPUT_DIR", Path.cwd() / "inbox"),
        policy=policy,
        _smtp=load_smtp() if with_smtp else None,
        _imap=load_imap() if with_imap else None,
        log_level=(_get("QUMAIL_LOG_LEVEL", "INFO") or "INFO").upper(),
        log_format=(_get("QUMAIL_LOG_FORMAT", "text") or "text").lower(),
    )


def get_passphrase(*, confirm: bool = False) -> str:
    """Read the keystore passphrase.

    Prefers the environment so a daemon can start unattended; falls back to an
    interactive prompt. Never echoes, never logs, and refuses to invent one.
    """
    from getpass import getpass

    env_value = os.environ.get("QUMAIL_KEYSTORE_PASSPHRASE")
    if env_value:
        return env_value

    if not sys.stdin.isatty():
        raise ConfigError(
            "QUMAIL_KEYSTORE_PASSPHRASE is not set and there is no terminal to "
            "prompt on. Set it in the environment for unattended runs."
        )

    passphrase = getpass("Keystore passphrase: ")
    if confirm and passphrase != getpass("Confirm passphrase: "):
        raise ConfigError("passphrases did not match")
    return passphrase

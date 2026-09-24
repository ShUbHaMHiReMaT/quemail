"""Logging with credential redaction.

Nothing in QuMail deliberately logs key material, but a stray exception
message or a config dump can leak one. The redacting filter is defence in
depth: it runs over every record, including tracebacks from dependencies.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from typing import Any

# Patterns for things that must never reach a log sink.
_SECRET_WORD = r"pass(?:word|phrase)?|secret|token|app_?pw|api[_-]?key|credential"

_REDACTIONS = (
    # key=value / key: value / "key": "value" for anything that smells secret.
    # No leading word boundary: real env names look like QUMAIL_SMTP_PASSWORD,
    # and "_" is a word character, so a boundary would never match there.
    re.compile(
        r"(?i)([\w.\-]*(?:" + _SECRET_WORD + r")[\w.\-]*)"
        r"[\"']?\s*[:=]\s*(\"[^\"]*\"|'[^']*'|\S+)"
    ),
    # Long hex runs: raw keys, shared secrets, private key material.
    # Threshold is 40 rather than 32 so that public identifiers stay legible:
    # message ids and fingerprints are 32 hex chars and are safe to log, while
    # real key material (a 32-byte key is 64 hex chars) is still scrubbed.
    re.compile(r"[0-9a-fA-F]{40,}"),
    # Base64-ish runs long enough to be key material rather than an ID.
    re.compile(r"\b[A-Za-z0-9+/]{60,}={0,2}\b"),
)

_PLACEHOLDER = "<redacted>"


def redact(text: str) -> str:
    """Replace anything that looks like a credential with a placeholder."""
    out = _REDACTIONS[0].sub(lambda m: m.group(1) + "=" + _PLACEHOLDER, text)
    for pattern in _REDACTIONS[1:]:
        out = pattern.sub(_PLACEHOLDER, out)
    return out


def _scrub(value: Any) -> Any:
    """Redact an interpolation argument without changing its type.

    Numbers are returned untouched. Coercing them to strings would scrub
    nothing -- a credential is never an int -- and would break every "%d" in
    the codebase with "a number is required, not str".
    """
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return redact(str(value))


class RedactingFilter(logging.Filter):
    """Scrubs every record on its way to a handler."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact(str(record.msg))
            if record.args:
                if isinstance(record.args, dict):
                    record.args = {k: _scrub(v) for k, v in record.args.items()}
                else:
                    record.args = tuple(_scrub(a) for a in record.args)
        except Exception:  # never let logging break the caller
            pass
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line -- for shipping to a log aggregator."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: str = "INFO", fmt: str = "text") -> None:
    """Install the root handler. Safe to call more than once."""
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stderr)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
        )
    handler.addFilter(RedactingFilter())
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Dependency chatter can include server banners and raw protocol lines.
    for noisy in ("smtplib", "imaplib"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)

"""One place that decides what a safe TLS connection looks like."""

from __future__ import annotations

import ssl

from ..logging_setup import get_logger

log = get_logger(__name__)

# TLS 1.2 is the floor. 1.0/1.1 are deprecated and 1.3 is preferred where the
# server supports it.
MINIMUM_TLS_VERSION = ssl.TLSVersion.TLSv1_2


def secure_context() -> ssl.SSLContext:
    """A context that verifies certificates and hostnames.

    `create_default_context` already enables both; they are asserted here so a
    future edit cannot quietly disable them.
    """
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = MINIMUM_TLS_VERSION

    if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
        raise RuntimeError("refusing to build a TLS context without verification")
    return context


def describe(sock: ssl.SSLSocket) -> str:
    """A short summary for the log. Never includes certificate contents."""
    try:
        version = sock.version() or "unknown"
        cipher = sock.cipher()
        return "%s / %s" % (version, cipher[0] if cipher else "unknown")
    except Exception:
        return "unknown"

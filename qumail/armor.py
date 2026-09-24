"""ASCII armouring of QuMail payloads for transport inside an email body.

Mail systems rewrap lines, convert encodings, append footers and quote
replies. The armour markers let a receiver find the exact payload again
regardless of what was added around it -- the previous approach of reading the
last line of the body broke the moment anything appended a signature.

Two block types travel this way:

    MESSAGE   a sealed envelope
    IDENTITY  a public key bundle, so someone can be introduced by email

An IDENTITY block asserts nothing on its own. It is a claim that some key
belongs to some address, which is exactly what an attacker would send, so the
receiver files it as a pending introduction for a human to accept rather than
importing it.
"""

from __future__ import annotations

import base64
import re

from .errors import EnvelopeError

LINE_LENGTH = 76

MESSAGE = "MESSAGE"
IDENTITY = "IDENTITY"

BEGIN_MARKER = "-----BEGIN QUMAIL MESSAGE-----"
END_MARKER = "-----END QUMAIL MESSAGE-----"

_BASE64_RE = re.compile(r"\A[A-Za-z0-9+/]*={0,2}\Z")
_MARKER_RE = re.compile(r"\A[A-Z]+\Z")


def _markers(kind: str) -> tuple:
    if not _MARKER_RE.match(kind):
        raise ValueError("block type must be uppercase letters")
    return (
        "-----BEGIN QUMAIL %s-----" % kind,
        "-----END QUMAIL %s-----" % kind,
    )


def _block_re(kind: str) -> re.Pattern:
    begin, end = _markers(kind)
    return re.compile(re.escape(begin) + r"(.*?)" + re.escape(end), re.DOTALL)


def armor(payload: str, kind: str = MESSAGE) -> str:
    """Wrap `payload` in a base64 armoured block of the given type."""
    begin, end = _markers(kind)
    encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")
    lines = [encoded[i : i + LINE_LENGTH] for i in range(0, len(encoded), LINE_LENGTH)]
    return "\n".join([begin, *lines, end])


def dearmor(text: str, *, max_bytes: int = 8 * 1024 * 1024, kind: str = MESSAGE) -> str:
    """Extract and decode the armoured block of `kind` in `text`.

    Exactly one block must be present. Two would be ambiguous -- an attacker
    could prepend their own block to a forwarded message and hope the receiver
    reads the wrong one.
    """
    if len(text) > max_bytes:
        raise EnvelopeError("mail body exceeds the maximum accepted size")

    blocks = _block_re(kind).findall(text)
    if not blocks:
        raise EnvelopeError("no QuMail %s block found in this message" % kind.lower())
    if len(blocks) > 1:
        raise EnvelopeError(
            "message contains multiple QuMail %s blocks; refusing to guess"
            % kind.lower()
        )

    # Strip whatever the mail path did to the whitespace, then be strict about
    # what is left: nothing but base64 should survive.
    body = "".join(blocks[0].split())
    if not _BASE64_RE.match(body):
        raise EnvelopeError("armoured block contains non-base64 characters")

    try:
        raw = base64.b64decode(body, validate=True)
    except (ValueError, TypeError) as exc:
        raise EnvelopeError("armoured block is not valid base64") from exc

    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EnvelopeError("armoured block is not valid UTF-8") from exc


def contains_block(text: str, kind: str = MESSAGE) -> bool:
    begin, end = _markers(kind)
    return begin in text and end in text

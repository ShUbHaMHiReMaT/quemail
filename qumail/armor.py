"""ASCII armouring of envelopes for transport inside an email body.

Mail systems rewrap lines, convert encodings, append footers and quote
replies. The armour markers let a receiver find the exact payload again
regardless of what was added around it -- the previous approach of reading the
last line of the body broke the moment anything appended a signature.
"""

from __future__ import annotations

import base64
import re

from .errors import EnvelopeError

BEGIN_MARKER = "-----BEGIN QUMAIL MESSAGE-----"
END_MARKER = "-----END QUMAIL MESSAGE-----"

LINE_LENGTH = 76

_BLOCK_RE = re.compile(
    re.escape(BEGIN_MARKER) + r"(.*?)" + re.escape(END_MARKER), re.DOTALL
)
_BASE64_RE = re.compile(r"\A[A-Za-z0-9+/]*={0,2}\Z")


def armor(payload: str) -> str:
    """Wrap `payload` in a base64 armoured block."""
    encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")
    lines = [encoded[i : i + LINE_LENGTH] for i in range(0, len(encoded), LINE_LENGTH)]
    return "\n".join([BEGIN_MARKER, *lines, END_MARKER])


def dearmor(text: str, *, max_bytes: int = 8 * 1024 * 1024) -> str:
    """Extract and decode the armoured block in `text`.

    Exactly one block must be present. Two would be ambiguous -- an attacker
    could prepend their own block to a forwarded message and hope the receiver
    reads the wrong one.
    """
    if len(text) > max_bytes:
        raise EnvelopeError("mail body exceeds the maximum accepted size")

    blocks = _BLOCK_RE.findall(text)
    if not blocks:
        raise EnvelopeError("no QuMail armoured block found in this message")
    if len(blocks) > 1:
        raise EnvelopeError("message contains multiple QuMail blocks; refusing to guess")

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


def contains_block(text: str) -> bool:
    return BEGIN_MARKER in text and END_MARKER in text

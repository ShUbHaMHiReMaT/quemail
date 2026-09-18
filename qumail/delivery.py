"""Writing decrypted messages to disk.

The original implementation built its output path as
`decrypted_{payload['id']}.html` from an attacker-controlled field and wrote
the plaintext into HTML unescaped. Both are fixed here: the id is validated as
32 hex characters before it is ever used in a path, the path is confirmed to
resolve inside the output directory, and any HTML rendering escapes the body.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .crypto.envelope import EnvelopeHeader, validate_message_id
from .errors import QuMailError
from .fsutil import atomic_write_bytes, atomic_write_text, ensure_private_dir
from .logging_setup import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class DeliveredMessage:
    message_id: str
    body_path: Path
    metadata_path: Path


def _safe_output_path(output_dir: Path, message_id: str, suffix: str) -> Path:
    """Resolve an output path, refusing anything outside `output_dir`."""
    validate_message_id(message_id)  # 32 hex chars: no separators, no "..", no drive
    root = output_dir.resolve()
    candidate = (root / ("%s%s" % (message_id, suffix))).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        raise QuMailError("refusing to write outside the output directory") from None
    return candidate


def _render_html(header: EnvelopeHeader, sender_address: str, body: str) -> str:
    """HTML view of a message. Every interpolated value is escaped."""
    received = datetime.fromtimestamp(header.timestamp, tz=timezone.utc).isoformat()
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">\n'
        "<title>QuMail message {msg_id}</title>\n"
        "<style>body{{font:14px/1.5 system-ui,sans-serif;margin:2rem;max-width:48rem}}"
        "dt{{font-weight:600}}dd{{margin:0 0 .5rem}}"
        "pre{{background:#f5f5f5;padding:1rem;border-radius:6px;white-space:pre-wrap;"
        "word-break:break-word}}</style></head><body>\n"
        "<h1>Decrypted QuMail message</h1>\n"
        "<dl><dt>From</dt><dd>{sender}</dd>"
        "<dt>Fingerprint</dt><dd><code>{fp}</code></dd>"
        "<dt>Subject</dt><dd>{subject}</dd>"
        "<dt>Sent</dt><dd>{sent}</dd>"
        "<dt>Message id</dt><dd><code>{msg_id}</code></dd></dl>\n"
        "<pre>{body}</pre>\n"
        "</body></html>\n"
    ).format(
        msg_id=html.escape(header.message_id),
        sender=html.escape(sender_address),
        fp=html.escape(header.sender_fingerprint),
        subject=html.escape(header.subject or "(none)"),
        sent=html.escape(received),
        body=html.escape(body),
    )


def deliver(
    output_dir: Path,
    header: EnvelopeHeader,
    sender_address: str,
    plaintext: bytes,
    *,
    write_html: bool = False,
) -> DeliveredMessage:
    """Write a decrypted message and its metadata with owner-only permissions."""
    ensure_private_dir(output_dir)

    body_path = _safe_output_path(output_dir, header.message_id, ".txt")
    metadata_path = _safe_output_path(output_dir, header.message_id, ".json")

    atomic_write_bytes(body_path, plaintext, private=True)
    atomic_write_text(
        metadata_path,
        json.dumps(
            {
                "message_id": header.message_id,
                "subject": header.subject,
                "sender_address": sender_address,
                "sender_fingerprint": header.sender_fingerprint,
                "recipient_fingerprint": header.recipient_fingerprint,
                "sent_at": datetime.fromtimestamp(
                    header.timestamp, tz=timezone.utc
                ).isoformat(),
                "protocol_version": header.version,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        private=True,
    )

    if write_html:
        atomic_write_text(
            _safe_output_path(output_dir, header.message_id, ".html"),
            _render_html(
                header, sender_address, plaintext.decode("utf-8", errors="replace")
            ),
            private=True,
        )

    log.info("delivered message %s to %s", header.message_id, body_path)
    return DeliveredMessage(
        message_id=header.message_id, body_path=body_path, metadata_path=metadata_path
    )

"""The message view the web inbox renders.

Received messages already land on disk as `<id>.txt` plus a `<id>.json`
sidecar. Sent messages are recorded here too, otherwise a conversation would
only ever show one side of itself.

Everything is grouped into threads by the *fingerprint* of the other party,
never by email address: the fingerprint is what was cryptographically
verified, and two people can claim the same address.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from ..crypto.envelope import validate_message_id
from ..fsutil import atomic_write_json, ensure_private_dir
from ..logging_setup import get_logger

log = get_logger(__name__)

MAX_BODY_PREVIEW = 4096


@dataclass(frozen=True)
class Message:
    message_id: str
    peer_fingerprint: str
    peer_address: str
    subject: str
    body: str
    timestamp: int
    outgoing: bool

    @property
    def when(self) -> str:
        return time.strftime("%d %b %H:%M", time.localtime(self.timestamp))


@dataclass(frozen=True)
class Thread:
    peer_fingerprint: str
    peer_address: str
    messages: List[Message]

    @property
    def latest(self) -> Optional[Message]:
        return self.messages[-1] if self.messages else None

    @property
    def pretty_fingerprint(self) -> str:
        fp = self.peer_fingerprint
        return " ".join(fp[i : i + 4] for i in range(0, len(fp), 4))


class MessageStore:
    """Reads delivered mail and records what was sent."""

    def __init__(self, inbox_dir: Path, sent_dir: Path) -> None:
        self.inbox_dir = inbox_dir
        self.sent_dir = sent_dir

    def record_sent(
        self,
        *,
        message_id: str,
        recipient_fingerprint: str,
        recipient_address: str,
        subject: str,
        body: bytes,
        timestamp: int,
    ) -> None:
        """Keep a local copy of an outgoing message.

        Stored in the clear, like the decrypted inbox: this host already holds
        the private key, so encrypting it here would protect nothing. The
        directory is owner-only.
        """
        ensure_private_dir(self.sent_dir)
        validate_message_id(message_id)
        atomic_write_json(
            self.sent_dir / ("%s.json" % message_id),
            {
                "message_id": message_id,
                "peer_fingerprint": recipient_fingerprint,
                "peer_address": recipient_address,
                "subject": subject,
                "body": body.decode("utf-8", errors="replace"),
                "timestamp": timestamp,
            },
            private=True,
        )

    def _load_received(self) -> List[Message]:
        messages: List[Message] = []
        if not self.inbox_dir.exists():
            return messages

        for sidecar in self.inbox_dir.glob("*.json"):
            try:
                meta = json.loads(sidecar.read_text(encoding="utf-8"))
                body_path = sidecar.with_suffix(".txt")
                body = (
                    body_path.read_text(encoding="utf-8", errors="replace")
                    if body_path.exists()
                    else ""
                )
                messages.append(
                    Message(
                        message_id=meta["message_id"],
                        peer_fingerprint=meta["sender_fingerprint"],
                        peer_address=meta.get("sender_address", "unknown"),
                        subject=meta.get("subject", ""),
                        body=body[:MAX_BODY_PREVIEW],
                        timestamp=int(
                            time.mktime(time.strptime(
                                meta["sent_at"][:19], "%Y-%m-%dT%H:%M:%S"
                            ))
                        ),
                        outgoing=False,
                    )
                )
            except (OSError, ValueError, KeyError) as exc:
                log.warning("skipping unreadable message %s: %s", sidecar.name, exc)
        return messages

    def _load_sent(self) -> List[Message]:
        messages: List[Message] = []
        if not self.sent_dir.exists():
            return messages

        for path in self.sent_dir.glob("*.json"):
            try:
                meta = json.loads(path.read_text(encoding="utf-8"))
                messages.append(
                    Message(
                        message_id=meta["message_id"],
                        peer_fingerprint=meta["peer_fingerprint"],
                        peer_address=meta.get("peer_address", "unknown"),
                        subject=meta.get("subject", ""),
                        body=str(meta.get("body", ""))[:MAX_BODY_PREVIEW],
                        timestamp=int(meta["timestamp"]),
                        outgoing=True,
                    )
                )
            except (OSError, ValueError, KeyError) as exc:
                log.warning("skipping unreadable sent message %s: %s", path.name, exc)
        return messages

    def threads(self) -> List[Thread]:
        """All conversations, most recently active first."""
        grouped: Dict[str, List[Message]] = {}
        addresses: Dict[str, str] = {}

        for message in self._load_received() + self._load_sent():
            grouped.setdefault(message.peer_fingerprint, []).append(message)
            # Prefer a real address over the "unknown" placeholder.
            if message.peer_address and message.peer_address != "unknown":
                addresses[message.peer_fingerprint] = message.peer_address

        threads = [
            Thread(
                peer_fingerprint=fingerprint,
                peer_address=addresses.get(fingerprint, "unknown"),
                messages=sorted(items, key=lambda m: m.timestamp),
            )
            for fingerprint, items in grouped.items()
        ]
        threads.sort(
            key=lambda t: t.latest.timestamp if t.latest else 0, reverse=True
        )
        return threads

    def thread_for(self, fingerprint: str) -> Optional[Thread]:
        return next(
            (t for t in self.threads() if t.peer_fingerprint == fingerprint), None
        )

    def count(self) -> int:
        return sum(len(t.messages) for t in self.threads())

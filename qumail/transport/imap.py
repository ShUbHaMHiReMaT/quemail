"""Fetching sealed envelopes over IMAP.

Uses UIDs rather than sequence numbers throughout: sequence numbers shift
whenever another client expunges a message, which for a long-running daemon
means acting on the wrong mail.
"""

from __future__ import annotations

import email
import imaplib
import re
from dataclasses import dataclass
from email.message import Message
from typing import Iterator, List, Optional

from ..config import ImapConfig
from ..errors import TransportError
from ..logging_setup import get_logger
from .tls import describe, secure_context

log = get_logger(__name__)

SEARCH_SUBJECT = "QuMail"
_UID_RE = re.compile(rb"\A[0-9]+\Z")

# imaplib's default (10 KiB) truncates literals; ours are ~2 KiB per envelope
# but attachments in the same mailbox can be far larger.
_MAX_IMAP_LINE = 10 * 1024 * 1024


@dataclass(frozen=True)
class FetchedMessage:
    uid: bytes
    raw: bytes
    from_header: str
    body_text: str


def _extract_text(message: Message, limit: int) -> str:
    """Concatenate the text/plain parts of a message, bounded by `limit`."""
    chunks: List[str] = []
    total = 0

    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_content_type() != "text/plain":
            continue
        try:
            payload = part.get_payload(decode=True)
        except Exception:
            continue
        if not payload:
            continue

        charset = part.get_content_charset() or "utf-8"
        try:
            text = payload.decode(charset, errors="replace")
        except (LookupError, UnicodeDecodeError):
            text = payload.decode("utf-8", errors="replace")

        total += len(text)
        if total > limit:
            chunks.append(text[: max(0, limit - (total - len(text)))])
            break
        chunks.append(text)

    return "\n".join(chunks)


class ImapReceiver:
    """A short-lived IMAP session. Use as a context manager."""

    def __init__(self, config: ImapConfig, *, max_message_bytes: int) -> None:
        self.config = config
        self.max_message_bytes = max_message_bytes
        self._client: Optional[imaplib.IMAP4_SSL] = None

    def __enter__(self) -> "ImapReceiver":
        self.connect()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def connect(self) -> None:
        previous_limit = imaplib._MAXLINE  # type: ignore[attr-defined]
        try:
            imaplib._MAXLINE = max(previous_limit, _MAX_IMAP_LINE)  # type: ignore[attr-defined]
            client = imaplib.IMAP4_SSL(
                host=self.config.host,
                port=self.config.port,
                ssl_context=secure_context(),
                timeout=self.config.timeout,
            )
        except imaplib.IMAP4.error as exc:
            raise TransportError("IMAP connection failed: %s" % exc) from exc
        except OSError as exc:
            raise TransportError(
                "could not reach IMAP server %s:%d"
                % (self.config.host, self.config.port)
            ) from exc

        sock = getattr(client, "sock", None)
        if sock is not None:
            log.debug("IMAP TLS established: %s", describe(sock))

        try:
            client.login(self.config.username, self.config.password)
            status, _ = client.select(self.config.mailbox)
            if status != "OK":
                raise TransportError(
                    "could not open mailbox %r" % self.config.mailbox
                )
        except imaplib.IMAP4.error as exc:
            try:
                client.logout()
            except Exception:
                pass
            raise TransportError(
                "IMAP login failed for %s -- check the account credentials and "
                "that IMAP access is enabled" % self.config.username
            ) from exc

        self._client = client

    def close(self) -> None:
        client, self._client = self._client, None
        if client is None:
            return
        for step in (client.close, client.logout):
            try:
                step()
            except Exception:
                pass  # the session is being discarded either way

    def _require_client(self) -> imaplib.IMAP4_SSL:
        if self._client is None:
            raise TransportError("IMAP session is not connected")
        return self._client

    def search_unseen(self, limit: int) -> List[bytes]:
        """UIDs of unread QuMail messages, oldest first."""
        client = self._require_client()
        try:
            status, data = client.uid("SEARCH", None, "UNSEEN", "SUBJECT", SEARCH_SUBJECT)
        except imaplib.IMAP4.error as exc:
            raise TransportError("IMAP search failed: %s" % exc) from exc
        if status != "OK" or not data or not data[0]:
            return []

        uids = [u for u in data[0].split() if _UID_RE.match(u)]
        return uids[:limit]

    def fetch(self, uid: bytes) -> Optional[FetchedMessage]:
        """Retrieve one message without marking it read.

        BODY.PEEK leaves the \\Seen flag alone so that a message is only ever
        marked read once it has actually been handled.
        """
        client = self._require_client()
        try:
            status, data = client.uid("FETCH", uid, "(RFC822.SIZE BODY.PEEK[])")
        except imaplib.IMAP4.error as exc:
            raise TransportError("IMAP fetch failed: %s" % exc) from exc
        if status != "OK" or not data:
            return None

        raw = next(
            (part[1] for part in data if isinstance(part, tuple) and len(part) > 1),
            None,
        )
        if not raw:
            return None
        if len(raw) > self.max_message_bytes:
            log.warning(
                "skipping UID %s: %d bytes exceeds the %d byte limit",
                uid.decode("ascii", "replace"),
                len(raw),
                self.max_message_bytes,
            )
            return None

        message = email.message_from_bytes(raw)
        return FetchedMessage(
            uid=uid,
            raw=raw,
            from_header=str(message.get("From", ""))[:320],
            body_text=_extract_text(message, self.max_message_bytes),
        )

    def mark_seen(self, uid: bytes) -> None:
        client = self._require_client()
        try:
            client.uid("STORE", uid, "+FLAGS", "(\\Seen)")
        except imaplib.IMAP4.error as exc:
            # Not fatal: the replay guard prevents double-processing anyway.
            log.warning("could not flag UID %s as seen: %s", uid, exc)

    def iter_pending(self, limit: int) -> Iterator[FetchedMessage]:
        for uid in self.search_unseen(limit):
            fetched = self.fetch(uid)
            if fetched is not None:
                yield fetched

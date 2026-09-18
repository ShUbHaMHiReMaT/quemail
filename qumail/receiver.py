"""The receive pipeline.

Every check a message must pass, in the order it is applied:

    1. body contains exactly one armoured block            (armor)
    2. envelope parses, within size limits, version matches (envelope)
    3. it is addressed to this keystore's fingerprint       (here)
    4. the sender's fingerprint is a trusted contact        (contacts)
    5. the signature verifies under that contact's key      (envelope)
    6. the KEM and AEAD verify, binding header to body      (envelope)
    7. the timestamp is fresh and the id is unseen          (replay)

A failure at any step drops that message and moves on. One hostile sender must
never be able to stop the daemon from processing everyone else's mail.
"""

from __future__ import annotations

import signal
import time
from dataclasses import dataclass

from .armor import contains_block, dearmor
from .config import Config
from .contacts import ContactStore
from .crypto.envelope import Envelope, open_envelope
from .crypto.keys import PrivateIdentity, PublicIdentity
from .delivery import DeliveredMessage, deliver
from .errors import QuMailError, TransportError, TrustError
from .logging_setup import get_logger
from .replay import ReplayGuard
from .transport.imap import FetchedMessage, ImapReceiver

log = get_logger(__name__)

# Reconnect backoff after a transport failure.
BACKOFF_INITIAL = 5
BACKOFF_MAX = 300


@dataclass
class PollResult:
    examined: int = 0
    delivered: int = 0
    rejected: int = 0


class Receiver:
    """Decrypts inbound QuMail messages and writes them out."""

    def __init__(
        self,
        config: Config,
        identity: PrivateIdentity,
        contacts: ContactStore,
        *,
        write_html: bool = False,
    ) -> None:
        self.config = config
        self.identity = identity
        self.contacts = contacts
        self.write_html = write_html
        self.replay = ReplayGuard(
            config.state_dir / "replay.json",
            max_age=config.policy.max_message_age,
            max_skew=config.policy.max_clock_skew,
        )
        self._stopping = False
        # UIDs already reported as untrusted, so the log says it once.
        self._deferred: set = set()

    # ---------- single message ----------

    def _resolve_sender(self, envelope: Envelope) -> PublicIdentity:
        """Find the trusted identity that claims to have sent this message.

        There is no "accept anyway" mode. An unknown sender's signing key is
        not in the envelope and could not be believed if it were, so a message
        from outside the contact store is unattributable by construction and
        stays sealed.
        """
        fingerprint = envelope.header.sender_fingerprint
        known = self.contacts.get(fingerprint)
        if known is not None:
            return known
        raise TrustError(
            "sender %s is not a trusted contact -- import their public identity "
            "with 'qumail import-contact' and this message will be read on the "
            "next poll" % fingerprint
        )

    def process_body(self, body_text: str) -> DeliveredMessage:
        """Run one mail body through the full pipeline."""
        envelope = Envelope.from_json(
            dearmor(body_text, max_bytes=self.config.policy.max_message_bytes)
        )
        header = envelope.header

        if header.recipient_fingerprint != self.identity.fingerprint:
            raise QuMailError(
                "message %s is addressed to %s, not to this keystore (%s)"
                % (header.message_id, header.recipient_fingerprint,
                   self.identity.fingerprint)
            )

        # Cheap checks before any asymmetric work, so replayed or stale mail
        # cannot be used to burn CPU.
        self.replay.check_freshness(header.timestamp)
        self.replay.check_unseen(header.message_id)

        sender = self._resolve_sender(envelope)
        plaintext = open_envelope(
            envelope, self.identity.kem, self.identity.public.kem, sender
        )

        # Recorded before delivery: a crash in between loses a message rather
        # than leaving it replayable.
        self.replay.record(header.message_id, header.timestamp)

        return deliver(
            self.config.output_dir,
            header,
            sender.address,
            plaintext,
            write_html=self.write_html,
        )

    def _process_fetched(self, message: FetchedMessage, result: PollResult) -> bool:
        """Handle one fetched mail. Returns True if it should be flagged read."""
        if not contains_block(message.body_text):
            return False  # not ours; leave it unread for the user's mail client

        result.examined += 1
        try:
            self.process_body(message.body_text)
            result.delivered += 1
            return True
        except TrustError as exc:
            # Recoverable: importing the contact later makes this message
            # readable, so leave it unread. Log once to avoid per-poll spam.
            result.rejected += 1
            if message.uid not in self._deferred:
                self._deferred.add(message.uid)
                log.warning(
                    "deferring message from %s: %s",
                    message.from_header or "unknown",
                    exc,
                )
            return False
        except QuMailError as exc:
            result.rejected += 1
            log.warning(
                "rejected message from %s: %s", message.from_header or "unknown", exc
            )
            # Flagged read: it will never become valid, and leaving it unread
            # means re-downloading and re-rejecting it forever.
            return True

    # ---------- polling ----------

    def poll_once(self) -> PollResult:
        """One connect / fetch / process / disconnect cycle."""
        result = PollResult()
        with ImapReceiver(
            self.config.imap, max_message_bytes=self.config.policy.max_message_bytes
        ) as session:
            for message in session.iter_pending(
                self.config.policy.max_messages_per_poll
            ):
                if self._stopping:
                    break
                if self._process_fetched(message, result):
                    session.mark_seen(message.uid)
        return result

    def request_stop(self, *_args: object) -> None:
        if not self._stopping:
            log.info("shutdown requested; finishing the current message")
        self._stopping = True

    def run_forever(self) -> None:
        """Poll until interrupted, backing off when the server is unreachable."""
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, self.request_stop)
            except (ValueError, AttributeError):
                pass  # not on the main thread, or not supported on this platform

        backoff = BACKOFF_INITIAL
        log.info(
            "polling %s every %ds as %s",
            self.config.imap.host,
            self.config.policy.poll_interval,
            self.identity.address,
        )

        while not self._stopping:
            try:
                result = self.poll_once()
                backoff = BACKOFF_INITIAL
                if result.examined:
                    log.info(
                        "poll complete: %d delivered, %d rejected",
                        result.delivered,
                        result.rejected,
                    )
                self._sleep(self.config.policy.poll_interval)
            except TransportError as exc:
                log.error("transport failure: %s; retrying in %ds", exc, backoff)
                self._sleep(backoff)
                backoff = min(backoff * 2, BACKOFF_MAX)

        log.info("receiver stopped")

    def _sleep(self, seconds: int) -> None:
        """Sleep in short slices so a signal is acted on promptly."""
        deadline = time.monotonic() + seconds
        while not self._stopping and time.monotonic() < deadline:
            time.sleep(min(1.0, deadline - time.monotonic()))

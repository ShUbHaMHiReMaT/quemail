"""Introductions: getting a first key to someone who has none of yours.

Encryption to a stranger is impossible -- you cannot seal a message to a key
you do not hold. Something has to travel in the clear first, and that
something is a public key, which is safe to send openly.

An invitation is an ordinary email carrying your public identity bundle. The
recipient's QuMail notices it and files it as *pending*. It is never imported
automatically: an identity block is only a claim that some key belongs to some
address, and accepting every such claim that lands in a mailbox would let
anyone plant a key under any name. A person accepts it, having seen the
fingerprint.

Once they accept and reply, their own key rides along with that reply and is
adopted on first contact, so the exchange completes itself from there.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .armor import IDENTITY, armor, contains_block, dearmor
from .crypto.keys import PublicIdentity
from .errors import EnvelopeError, QuMailError
from .fsutil import atomic_write_json, ensure_private_dir, read_json
from .logging_setup import get_logger

log = get_logger(__name__)

MAX_PENDING = 100

INVITATION_SUBJECT = "[QuMail] Secure contact request"

INVITATION_TEXT = """\
{sender} would like to exchange end-to-end encrypted mail with you.

Their QuMail fingerprint is:

    {fingerprint}

If you already use QuMail, this contact request will appear in your inbox --
accept it there, check that the fingerprint above matches what they tell you
in person or over the phone, and reply. Your own key travels with that reply,
so nothing further needs to be exchanged by hand.

If you do not use QuMail yet, it is at:
    https://github.com/ShUbHaMHiReMaT/quemail

Nothing in this email is secret. It carries a public key, which is meant to be
seen; it is the fingerprint you should verify through some other channel.

{block}
"""


def build_invitation_body(identity: PublicIdentity) -> str:
    """The plaintext body of an invitation email."""
    return INVITATION_TEXT.format(
        sender=identity.address,
        fingerprint=identity.pretty_fingerprint(),
        block=armor(identity.to_json(), IDENTITY),
    )


def parse_invitation(body_text: str) -> PublicIdentity:
    """Extract the identity offered by an invitation email.

    Raises `EnvelopeError` if there is no block, or if the bundle inside is
    malformed or its claimed fingerprint disagrees with its keys.
    """
    return PublicIdentity.from_json(dearmor(body_text, kind=IDENTITY))


def looks_like_invitation(body_text: str) -> bool:
    return contains_block(body_text, IDENTITY)


@dataclass(frozen=True)
class PendingInvite:
    """An identity someone has offered, awaiting a human decision."""

    identity: PublicIdentity
    from_header: str
    received_at: int

    @property
    def fingerprint(self) -> str:
        return self.identity.fingerprint

    def to_dict(self) -> dict:
        return {
            "identity": self.identity.to_dict(),
            "from_header": self.from_header,
            "received_at": self.received_at,
        }


class InviteStore:
    """Contact requests waiting to be accepted or dismissed.

    Kept separate from the contact store on purpose. Nothing here is trusted;
    moving an entry across that line is a deliberate act.
    """

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def _path_for(self, fingerprint: str) -> Path:
        # Fingerprints are validated hex, so this cannot escape the directory.
        if len(fingerprint) != 32 or not all(c in "0123456789abcdef" for c in fingerprint):
            raise QuMailError("invalid fingerprint")
        return self.directory / ("%s.json" % fingerprint)

    def add(self, identity: PublicIdentity, from_header: str) -> bool:
        """File an offered identity. Returns True if it was new."""
        ensure_private_dir(self.directory)
        path = self._path_for(identity.fingerprint)
        if path.exists():
            return False
        if len(list(self.directory.glob("*.json"))) >= MAX_PENDING:
            log.warning("pending invitation list is full; ignoring %s", identity.address)
            return False

        atomic_write_json(
            path,
            PendingInvite(
                identity=identity,
                from_header=from_header[:320],
                received_at=int(time.time()),
            ).to_dict(),
            private=True,
        )
        log.info(
            "contact request from %s (%s) awaiting acceptance",
            identity.address,
            identity.fingerprint,
        )
        return True

    def all(self) -> List[PendingInvite]:
        if not self.directory.exists():
            return []
        invites = []
        for path in sorted(self.directory.glob("*.json")):
            try:
                data = read_json(path)
                invites.append(
                    PendingInvite(
                        identity=PublicIdentity.from_dict(data["identity"]),
                        from_header=str(data.get("from_header", "")),
                        received_at=int(data.get("received_at", 0)),
                    )
                )
            except (OSError, ValueError, KeyError, EnvelopeError) as exc:
                log.warning("dropping unreadable contact request %s: %s", path.name, exc)
        return invites

    def get(self, fingerprint: str) -> Optional[PendingInvite]:
        return next((i for i in self.all() if i.fingerprint == fingerprint), None)

    def remove(self, fingerprint: str) -> bool:
        path = self._path_for(fingerprint)
        if not path.exists():
            return False
        path.unlink()
        return True

    def __len__(self) -> int:
        return len(self.all())

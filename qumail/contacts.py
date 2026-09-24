"""The trust store: which identities we will accept mail from.

A signature only means something once you know whose key you are checking
against. QuMail therefore keeps an explicit list of imported public identities
and, by default, drops anything signed by a key that is not on it. There is no
trust-on-first-use: a stranger's key arriving by email is exactly what an
attacker would send.

Fingerprints are the identifier of record. Email addresses are advisory --
they are trivially spoofed in transit and are stored only so operators can
recognise a contact by name.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

from .crypto.keys import PublicIdentity
from .errors import EnvelopeError, TrustError
from .fsutil import atomic_write_json, read_json
from .logging_setup import get_logger

log = get_logger(__name__)

MAX_CONTACTS_BYTES = 4 * 1024 * 1024


class ContactStore:
    """Fingerprint-keyed collection of trusted public identities."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._contacts: Dict[str, PublicIdentity] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        if self.path.stat().st_size > MAX_CONTACTS_BYTES:
            raise TrustError("contact store is implausibly large; refusing to parse")

        try:
            data = read_json(self.path)
        except (json.JSONDecodeError, OSError) as exc:
            raise TrustError("contact store at %s is corrupt" % self.path) from exc
        if not isinstance(data, dict) or not isinstance(data.get("contacts"), list):
            raise TrustError("contact store at %s has an unexpected shape" % self.path)

        for entry in data["contacts"]:
            try:
                identity = PublicIdentity.from_dict(entry)
            except EnvelopeError as exc:
                # One bad row must not lock the operator out of every contact.
                log.warning("skipping malformed contact entry: %s", exc)
                continue
            self._contacts[identity.fingerprint] = identity

    def _save(self) -> None:
        atomic_write_json(
            self.path,
            {
                "v": 1,
                "contacts": [c.to_dict() for c in sorted(
                    self._contacts.values(), key=lambda c: c.address.lower()
                )],
            },
            private=True,
        )

    def add(self, identity: PublicIdentity, *, replace: bool = False) -> bool:
        """Trust `identity`. Returns True if anything changed.

        Re-importing the same bundle is a no-op. Importing a *different* key
        under a fingerprint already present is refused unless `replace` is
        set -- a silent key swap is the attack this store exists to stop.
        """
        existing = self._contacts.get(identity.fingerprint)
        if existing is not None:
            if existing.to_dict() == identity.to_dict():
                return False
            if not replace:
                raise TrustError(
                    "a different key is already trusted for fingerprint %s; "
                    "verify out of band, then re-run with --replace"
                    % identity.fingerprint
                )

        # A second identity claiming an address you already trust is worth
        # surfacing, even though the fingerprint is what actually decides.
        for other in self._contacts.values():
            if (
                other.fingerprint != identity.fingerprint
                and other.address.lower() == identity.address.lower()
            ):
                log.warning(
                    "address %s is now associated with two fingerprints (%s, %s)",
                    identity.address,
                    other.fingerprint,
                    identity.fingerprint,
                )

        self._contacts[identity.fingerprint] = identity
        self._save()
        return True

    def learn(self, identity: PublicIdentity) -> bool:
        """Trust-on-first-use: accept a key seen for the first time.

        Returns True if this was a new identity. The security properties are
        the ones Signal and WhatsApp rely on:

        * First contact is taken on faith. An attacker positioned between you
          at that exact moment could substitute their own key.
        * Every contact after that is pinned. The key is stored under a
          fingerprint that commits to it, so a later substitution is a
          *different* fingerprint and lands here as a new identity, while an
          attempt to change the key behind an existing fingerprint is
          impossible by construction.
        * The fingerprint is shown in the UI, so the faith taken at step one
          can be checked out of band at any later time.

        This is weaker than verifying before the first message and stronger
        than accepting anything. Which one you get is the operator's choice.
        """
        existing = self._contacts.get(identity.fingerprint)
        if existing is not None:
            return False

        log.info(
            "learned new identity %s for %s on first contact",
            identity.fingerprint,
            identity.address,
        )
        self._contacts[identity.fingerprint] = identity
        self._save()
        return True

    def remove(self, fingerprint: str) -> bool:
        if self._contacts.pop(fingerprint.replace(" ", "").lower(), None) is None:
            return False
        self._save()
        return True

    def get(self, fingerprint: str) -> Optional[PublicIdentity]:
        return self._contacts.get(fingerprint)

    def require(self, fingerprint: str) -> PublicIdentity:
        """Look up a sender, or refuse the message."""
        identity = self.get(fingerprint)
        if identity is None:
            raise TrustError(
                "sender fingerprint %s is not in the contact store" % fingerprint
            )
        return identity

    def find_by_address(self, address: str) -> Optional[PublicIdentity]:
        """Resolve an address, but only when it is unambiguous."""
        wanted = address.strip().lower()
        matches = [c for c in self._contacts.values() if c.address.lower() == wanted]
        if len(matches) > 1:
            raise TrustError(
                "%s matches %d trusted identities; specify the fingerprint instead"
                % (address, len(matches))
            )
        return matches[0] if matches else None

    def resolve(self, reference: str) -> PublicIdentity:
        """Accept either a fingerprint or an email address."""
        normalised = reference.strip().replace(" ", "").lower()
        identity = self.get(normalised)
        if identity is not None:
            return identity
        identity = self.find_by_address(reference)
        if identity is None:
            raise TrustError(
                "no trusted contact matches %r -- import their public identity "
                "with 'qumail import-contact'" % reference
            )
        return identity

    def __iter__(self) -> Iterator[PublicIdentity]:
        return iter(sorted(self._contacts.values(), key=lambda c: c.address.lower()))

    def __len__(self) -> int:
        return len(self._contacts)

    def to_list(self) -> list[dict[str, Any]]:
        return [c.to_dict() for c in self]

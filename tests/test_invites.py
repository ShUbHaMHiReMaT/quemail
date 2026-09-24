"""Contact requests: how a first key reaches someone who holds none of yours."""

from __future__ import annotations

import pytest

from qumail.armor import IDENTITY, armor, contains_block
from qumail.contacts import ContactStore
from qumail.crypto.envelope import seal
from qumail.errors import EnvelopeError, QuMailError
from qumail.invites import (
    InviteStore,
    build_invitation_body,
    looks_like_invitation,
    parse_invitation,
)
from qumail.receiver import Receiver
from qumail.transport.imap import FetchedMessage
from qumail.transport.smtp import build_message


class TestInvitationBody:
    def test_round_trip(self, alice):
        body = build_invitation_body(alice.public)
        parsed = parse_invitation(body)
        assert parsed.fingerprint == alice.fingerprint
        assert parsed.address == alice.address

    def test_body_shows_the_fingerprint_for_verification(self, alice):
        assert alice.public.pretty_fingerprint() in build_invitation_body(alice.public)

    def test_carries_no_private_key(self, alice):
        import base64

        body = build_invitation_body(alice.public)
        for secret in (alice.signing_key, alice.kem.x25519, alice.kem.mlkem):
            assert base64.b64encode(secret).decode() not in body

    def test_detection(self, alice, bob):
        assert looks_like_invitation(build_invitation_body(alice.public))
        assert not looks_like_invitation("just a normal email")
        # A sealed message is not an invitation.
        envelope = seal(alice, bob.public, b"hi")
        assert not looks_like_invitation(
            build_message(
                envelope, from_address="a@example.com", to_address="b@example.com"
            ).get_payload(decode=True).decode()
        )

    def test_an_edited_bundle_is_rejected(self, alice, bob):
        """The fingerprint inside the bundle must match its keys."""
        import base64
        import json

        data = alice.public.to_dict()
        data["sig_pk"] = base64.b64encode(bob.public.signing_key).decode()
        with pytest.raises(EnvelopeError, match="fingerprint does not match"):
            parse_invitation(armor(json.dumps(data), IDENTITY))

    def test_missing_block(self):
        with pytest.raises(EnvelopeError, match="no QuMail identity block"):
            parse_invitation("hello, no key here")


class TestInviteStore:
    def test_add_and_list(self, config, alice):
        store = InviteStore(config.state_dir / "pending")
        assert store.add(alice.public, "alice@example.com") is True
        assert len(store) == 1
        assert store.get(alice.fingerprint).identity.fingerprint == alice.fingerprint

    def test_adding_twice_is_a_no_op(self, config, alice):
        store = InviteStore(config.state_dir / "pending")
        assert store.add(alice.public, "a@example.com") is True
        assert store.add(alice.public, "a@example.com") is False
        assert len(store) == 1

    def test_persists_across_instances(self, config, alice):
        InviteStore(config.state_dir / "pending").add(alice.public, "a@example.com")
        assert len(InviteStore(config.state_dir / "pending")) == 1

    def test_remove(self, config, alice):
        store = InviteStore(config.state_dir / "pending")
        store.add(alice.public, "a@example.com")
        assert store.remove(alice.fingerprint) is True
        assert store.remove(alice.fingerprint) is False

    @pytest.mark.parametrize(
        "evil", ["../escape", "..\\escape", "a" * 31, "A" * 32, "", "/etc/passwd"]
    )
    def test_fingerprints_cannot_steer_the_path(self, config, evil):
        store = InviteStore(config.state_dir / "pending")
        with pytest.raises(QuMailError):
            store.remove(evil)

    def test_unreadable_entries_are_dropped_not_fatal(self, config, alice):
        store = InviteStore(config.state_dir / "pending")
        store.add(alice.public, "a@example.com")
        (config.state_dir / "pending" / ("deadbeef" * 4 + ".json")).write_text(
            "{not json"
        )
        assert len(store.all()) == 1


class TestReceiverHandlesInvitations:
    @pytest.fixture
    def receiver(self, config, bob):
        return Receiver(config, bob, ContactStore(config.contacts_path))

    def _fetched(self, body, uid=b"1"):
        return FetchedMessage(
            uid=uid, raw=b"", from_header="alice@example.com", body_text=body
        )

    def test_invitation_is_filed_not_imported(self, receiver, alice, config):
        from qumail.receiver import PollResult

        result = PollResult()
        handled = receiver._process_fetched(
            self._fetched(build_invitation_body(alice.public)), result
        )

        assert handled is True
        assert result.invitations == 1
        # Filed as pending...
        assert len(InviteStore(config.state_dir / "pending")) == 1
        # ...and emphatically NOT trusted.
        assert ContactStore(config.contacts_path).get(alice.fingerprint) is None

    def test_an_already_trusted_sender_creates_no_request(self, receiver, alice, config):
        from qumail.receiver import PollResult

        receiver.contacts.add(alice.public)
        receiver._process_fetched(
            self._fetched(build_invitation_body(alice.public)), PollResult()
        )
        assert len(InviteStore(config.state_dir / "pending")) == 0

    def test_a_malformed_invitation_is_dropped(self, receiver):
        from qumail.receiver import PollResult

        result = PollResult()
        body = armor("not an identity at all", IDENTITY)
        assert receiver._process_fetched(self._fetched(body), result) is True
        assert result.rejected == 1

    def test_accepting_then_receiving_works_end_to_end(self, receiver, alice, bob, config):
        """The full introduction: request, accept, then encrypted mail flows."""
        from qumail.receiver import PollResult

        # 1. Alice's contact request arrives and is filed.
        receiver._process_fetched(
            self._fetched(build_invitation_body(alice.public)), PollResult()
        )
        invites = InviteStore(config.state_dir / "pending")
        pending = invites.get(alice.fingerprint)
        assert pending is not None

        # 2. Bob accepts it.
        receiver.contacts.add(pending.identity)
        invites.remove(pending.fingerprint)

        # 3. Alice's encrypted mail now decrypts.
        envelope = seal(alice, bob.public, b"now we are connected")
        body = build_message(
            envelope, from_address=alice.address, to_address=bob.address
        ).get_payload(decode=True).decode()

        assert receiver.process_body(body).body_path.read_bytes() == b"now we are connected"


class TestArmorBlockTypes:
    def test_types_do_not_collide(self):
        message_block = armor("payload")
        identity_block = armor("payload", IDENTITY)

        assert contains_block(message_block)
        assert not contains_block(message_block, IDENTITY)
        assert contains_block(identity_block, IDENTITY)
        assert not contains_block(identity_block)

    def test_rejects_an_invalid_block_type(self):
        with pytest.raises(ValueError):
            armor("payload", "not-a-valid-type")

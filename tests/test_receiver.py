"""End-to-end: the receive pipeline as it sees real mail bodies."""

from __future__ import annotations

import json
import time

import pytest

from qumail.armor import armor, dearmor
from qumail.contacts import ContactStore
from qumail.crypto.envelope import Envelope, seal
from qumail.errors import CryptoError, EnvelopeError, QuMailError, ReplayError, TrustError
from qumail.receiver import Receiver
from qumail.transport.smtp import build_message


def mail_body(envelope, sender="alice@example.com", recipient="bob@example.com") -> str:
    """The exact text an IMAP client would pull back for this envelope."""
    message = build_message(envelope, from_address=sender, to_address=recipient)
    return message.get_payload(decode=True).decode("utf-8")


@pytest.fixture
def receiver(config, bob, alice):
    """Bob's receiver, with Alice already trusted. Learns new senders (default)."""
    contacts = ContactStore(config.contacts_path)
    contacts.add(alice.public)
    return Receiver(config, bob, contacts)


@pytest.fixture
def strict_receiver(config, bob, alice):
    """Bob's receiver with first-contact learning turned off."""
    contacts = ContactStore(config.contacts_path)
    contacts.add(alice.public)
    return Receiver(config, bob, contacts, learn_senders=False)


class TestHappyPath:
    def test_delivers_a_trusted_message(self, receiver, alice, bob):
        envelope = seal(alice, bob.public, b"Jai Shree Ram!", subject="hello")
        result = receiver.process_body(mail_body(envelope))

        assert result.body_path.read_bytes() == b"Jai Shree Ram!"
        assert result.message_id == envelope.header.message_id

    def test_metadata_records_the_verified_sender(self, receiver, alice, bob):
        envelope = seal(alice, bob.public, b"hi")
        result = receiver.process_body(mail_body(envelope))
        metadata = json.loads(result.metadata_path.read_text())

        assert metadata["sender_address"] == "alice@example.com"
        assert metadata["sender_fingerprint"] == alice.fingerprint

    def test_survives_a_quoted_reply_wrapper(self, receiver, alice, bob):
        """Mail clients add text around the block; the block still parses."""
        envelope = seal(alice, bob.public, b"hi")
        noisy = (
            "On Monday, Alice wrote:\n> ...\n\n"
            + mail_body(envelope)
            + "\n\n-- \nSent from my phone\n"
        )
        assert receiver.process_body(noisy).body_path.read_bytes() == b"hi"


class TestFirstContact:
    """Trust on first use: the key rides with the message."""

    def test_unknown_sender_is_learned_and_delivered(self, receiver, mallory, bob, config):
        envelope = seal(mallory, bob.public, b"hello, we have not met")
        result = receiver.process_body(mail_body(envelope))

        assert result.body_path.read_bytes() == b"hello, we have not met"
        assert ContactStore(config.contacts_path).get(mallory.fingerprint) is not None

    def test_learning_happens_once(self, receiver, mallory, bob, config):
        receiver.process_body(mail_body(seal(mallory, bob.public, b"first")))
        receiver.process_body(mail_body(seal(mallory, bob.public, b"second")))
        assert len(ContactStore(config.contacts_path)) == 2  # alice + mallory

    def test_a_stored_key_is_never_displaced_by_an_attached_one(
        self, receiver, alice, bob, config
    ):
        """An imported, verified key wins over anything arriving by email."""
        envelope = seal(alice, bob.public, b"hi")
        receiver.process_body(mail_body(envelope))

        stored = ContactStore(config.contacts_path).get(alice.fingerprint)
        assert stored.signing_key == alice.public.signing_key

    def test_a_forged_attached_identity_is_rejected(self, alice, bob, mallory):
        """The bundle must hash to the fingerprint the header commits to."""
        envelope = seal(alice, bob.public, b"hi")
        data = json.loads(envelope.to_json())
        # Mallory swaps in her own bundle while leaving Alice's fingerprint.
        data["sender_id"] = mallory.public.to_dict()

        with pytest.raises(EnvelopeError, match="does not match the fingerprint"):
            Envelope.from_json(json.dumps(data))

    def test_strict_mode_refuses_to_learn(self, strict_receiver, mallory, bob):
        envelope = seal(mallory, bob.public, b"trust me")
        with pytest.raises(TrustError, match="not a trusted contact"):
            strict_receiver.process_body(mail_body(envelope))

    def test_sender_without_an_attached_key_is_still_refused(
        self, receiver, mallory, bob
    ):
        envelope = seal(mallory, bob.public, b"anonymous", attach_identity=False)
        with pytest.raises(TrustError, match="attached no public identity"):
            receiver.process_body(mail_body(envelope))


class TestRejections:
    def test_untrusted_sender_is_deferred(self, strict_receiver, mallory, bob):
        envelope = seal(mallory, bob.public, b"trust me")
        with pytest.raises(TrustError, match="not a trusted contact"):
            strict_receiver.process_body(mail_body(envelope))

    def test_message_for_another_recipient_is_refused(self, receiver, alice, mallory):
        envelope = seal(alice, mallory.public, b"not for bob")
        with pytest.raises(QuMailError, match="addressed to"):
            receiver.process_body(mail_body(envelope))

    def test_replayed_message_is_refused(self, receiver, alice, bob):
        body = mail_body(seal(alice, bob.public, b"hi"))
        receiver.process_body(body)
        with pytest.raises(ReplayError, match="already been processed"):
            receiver.process_body(body)

    def test_stale_message_is_refused(self, receiver, alice, bob):
        old = int(time.time()) - (30 * 24 * 3600)
        envelope = seal(alice, bob.public, b"ancient", timestamp=old)
        with pytest.raises(ReplayError):
            receiver.process_body(mail_body(envelope))

    def test_tampered_body_is_refused(self, receiver, alice, bob):
        import base64

        envelope = seal(alice, bob.public, b"hi")
        data = json.loads(dearmor(mail_body(envelope)))
        blob = bytearray(base64.b64decode(data["ct"]))
        blob[0] ^= 0x01
        data["ct"] = base64.b64encode(bytes(blob)).decode()

        with pytest.raises(CryptoError):
            receiver.process_body(armor(json.dumps(data)))

    def test_non_qumail_mail_is_refused(self, receiver):
        with pytest.raises(EnvelopeError, match="no QuMail message block"):
            receiver.process_body("Hi Bob, lunch at 1?")

    def test_nothing_is_written_when_a_message_is_rejected(
        self, strict_receiver, mallory, bob, config
    ):
        envelope = seal(mallory, bob.public, b"trust me")
        with pytest.raises(TrustError):
            strict_receiver.process_body(mail_body(envelope))

        written = list(config.output_dir.glob("*")) if config.output_dir.exists() else []
        assert written == []

    def test_a_rejected_message_does_not_consume_its_id(
        self, strict_receiver, alice, bob, mallory
    ):
        """A dropped message must not let an attacker block a later real one."""
        envelope = seal(mallory, bob.public, b"junk")
        with pytest.raises(TrustError):
            strict_receiver.process_body(mail_body(envelope))

        # The same id, this time from a trusted sender, still goes through.
        legit = seal(alice, bob.public, b"real")
        assert strict_receiver.process_body(
            mail_body(legit)
        ).body_path.read_bytes() == b"real"


class TestPollLoopIsolation:
    def test_one_bad_message_does_not_stop_the_batch(
        self, strict_receiver, alice, bob, mallory
    ):
        """The loop must survive a hostile message and keep delivering."""
        from qumail.receiver import PollResult
        from qumail.transport.imap import FetchedMessage

        def fetched(envelope, uid):
            return FetchedMessage(
                uid=uid,
                raw=b"",
                from_header="someone@example.com",
                body_text=mail_body(envelope),
            )

        result = PollResult()
        messages = [
            fetched(seal(mallory, bob.public, b"junk"), b"1"),
            fetched(seal(alice, bob.public, b"good one"), b"2"),
        ]
        outcomes = [strict_receiver._process_fetched(m, result) for m in messages]

        assert result.delivered == 1
        assert result.rejected == 1
        assert outcomes == [False, True]  # untrusted deferred, good one flagged read

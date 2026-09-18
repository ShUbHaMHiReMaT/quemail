"""The wire format: sealing, opening, and the attacks it must survive."""

from __future__ import annotations

import base64
import json

import pytest

from qumail.armor import armor, dearmor
from qumail.crypto.envelope import (
    MAX_PLAINTEXT_BYTES,
    Envelope,
    EnvelopeHeader,
    _signed_bytes,
    new_message_id,
    open_envelope,
    seal,
    validate_message_id,
)
from qumail.errors import CryptoError, EnvelopeError


def _open(envelope, recipient, sender):
    return open_envelope(envelope, recipient.kem, recipient.public.kem, sender.public)


def _mutate(envelope: Envelope, **header_changes) -> Envelope:
    """Rebuild an envelope with edited header fields, signature untouched."""
    data = json.loads(envelope.to_json())
    data["hdr"].update(header_changes)
    return Envelope.from_json(json.dumps(data))


class TestRoundTrip:
    def test_seal_and_open(self, alice, bob):
        envelope = seal(alice, bob.public, b"hello", subject="greeting")
        assert _open(envelope, bob, alice) == b"hello"

    def test_survives_json_serialisation(self, alice, bob):
        envelope = seal(alice, bob.public, b"hello")
        assert _open(Envelope.from_json(envelope.to_json()), bob, alice) == b"hello"

    def test_survives_armouring(self, alice, bob):
        envelope = seal(alice, bob.public, b"hello")
        assert dearmor(armor(envelope.to_json())) == envelope.to_json()

    def test_binary_and_unicode_bodies(self, alice, bob):
        for body in (b"\x00\xff\xfe binary", "नमस्ते 🔐".encode("utf-8"), b""):
            envelope = seal(alice, bob.public, body)
            assert _open(envelope, bob, alice) == body

    def test_body_never_appears_in_the_wire_form(self, alice, bob):
        secret = b"the merger closes on Friday"
        envelope = seal(alice, bob.public, secret, subject="board meeting")
        wire = envelope.to_json().encode("utf-8")
        assert secret not in wire
        assert secret not in base64.b64decode(json.loads(envelope.to_json())["ct"])


class TestTampering:
    def test_flipped_ciphertext_bit(self, alice, bob):
        envelope = seal(alice, bob.public, b"hello")
        broken = bytearray(envelope.ciphertext)
        broken[0] ^= 0x01
        with pytest.raises(CryptoError):
            _open(
                Envelope(
                    envelope.header,
                    envelope.kem_ciphertext,
                    envelope.nonce,
                    bytes(broken),
                    envelope.signature,
                ),
                bob,
                alice,
            )

    def test_edited_subject_breaks_decryption(self, alice, bob):
        """Headers are associated data: editing one invalidates the body."""
        envelope = seal(alice, bob.public, b"hello", subject="original")
        with pytest.raises(CryptoError):
            _open(_mutate(envelope, subject="rewritten"), bob, alice)

    def test_edited_timestamp_breaks_decryption(self, alice, bob):
        envelope = seal(alice, bob.public, b"hello")
        with pytest.raises(CryptoError):
            _open(_mutate(envelope, ts=envelope.header.timestamp + 1), bob, alice)

    def test_edited_message_id_breaks_decryption(self, alice, bob):
        envelope = seal(alice, bob.public, b"hello")
        with pytest.raises(CryptoError):
            _open(_mutate(envelope, id=new_message_id()), bob, alice)

    def test_swapped_kem_ciphertext(self, alice, bob):
        first = seal(alice, bob.public, b"one")
        second = seal(alice, bob.public, b"two")
        with pytest.raises(CryptoError):
            _open(
                Envelope(
                    first.header,
                    second.kem_ciphertext,
                    first.nonce,
                    first.ciphertext,
                    first.signature,
                ),
                bob,
                alice,
            )


class TestImpersonation:
    def test_wrong_claimed_sender_is_rejected(self, alice, bob, mallory):
        envelope = seal(alice, bob.public, b"hello")
        with pytest.raises(CryptoError):
            _open(envelope, bob, mallory)

    def test_forged_signature_is_rejected(self, alice, bob, mallory):
        envelope = seal(alice, bob.public, b"hello")
        forged = Envelope(
            envelope.header,
            envelope.kem_ciphertext,
            envelope.nonce,
            envelope.ciphertext,
            mallory.sign(
                _signed_bytes(
                    envelope.header,
                    envelope.kem_ciphertext,
                    envelope.nonce,
                    envelope.ciphertext,
                )
            ),
        )
        with pytest.raises(CryptoError):
            _open(forged, bob, alice)

    def test_signature_stripping_and_resigning_fails(self, alice, bob, mallory):
        """The attack encrypt-then-sign is usually vulnerable to.

        Mallory intercepts Alice's ciphertext, relabels it as her own and
        re-signs it. The signature is then valid, but the sender fingerprint
        is inside the KEM context, so the key no longer derives.
        """
        original = seal(alice, bob.public, b"hello")
        header = EnvelopeHeader(
            version=original.header.version,
            message_id=original.header.message_id,
            timestamp=original.header.timestamp,
            sender_fingerprint=mallory.fingerprint,
            recipient_fingerprint=original.header.recipient_fingerprint,
            subject=original.header.subject,
        )
        relabelled = Envelope(
            header,
            original.kem_ciphertext,
            original.nonce,
            original.ciphertext,
            mallory.sign(
                _signed_bytes(
                    header, original.kem_ciphertext, original.nonce, original.ciphertext
                )
            ),
        )
        with pytest.raises(CryptoError):
            _open(relabelled, bob, mallory)

    def test_third_party_cannot_read(self, alice, bob, mallory):
        envelope = seal(alice, bob.public, b"hello")
        with pytest.raises(CryptoError):
            open_envelope(envelope, mallory.kem, mallory.public.kem, alice.public)


class TestParsing:
    @pytest.mark.parametrize(
        "bad_id",
        [
            "../../../etc/passwd",
            "..\\..\\windows\\system32",
            "C:/windows/system32",
            "abc",
            "A" * 32,          # uppercase hex
            "g" * 32,          # not hex
            "0" * 31,
            "0" * 33,
            "",
            None,
            12345,
            "0" * 32 + "\n",
        ],
    )
    def test_message_ids_are_strictly_validated(self, bad_id):
        with pytest.raises(EnvelopeError):
            validate_message_id(bad_id)

    def test_generated_ids_are_valid_and_unique(self):
        ids = {new_message_id() for _ in range(500)}
        assert len(ids) == 500
        for value in ids:
            validate_message_id(value)

    @pytest.mark.parametrize(
        "payload",
        [
            "not json at all",
            "[]",
            '"a string"',
            "{}",
            '{"hdr": {}}',
            '{"hdr": null, "kem": {}, "nonce": "", "ct": "", "sig": ""}',
        ],
    )
    def test_malformed_envelopes_are_rejected(self, payload):
        with pytest.raises(EnvelopeError):
            Envelope.from_json(payload)

    def test_oversized_envelope_is_rejected_before_parsing(self):
        with pytest.raises(EnvelopeError, match="maximum accepted size"):
            Envelope.from_json("x" * (9 * 1024 * 1024))

    def test_wrong_protocol_version_is_rejected(self, alice, bob):
        envelope = seal(alice, bob.public, b"hello")
        data = json.loads(envelope.to_json())
        data["hdr"]["v"] = 99
        with pytest.raises(EnvelopeError, match="unsupported envelope version"):
            Envelope.from_json(json.dumps(data))

    def test_non_base64_fields_are_rejected(self, alice, bob):
        envelope = seal(alice, bob.public, b"hello")
        data = json.loads(envelope.to_json())
        data["nonce"] = "!!!not base64!!!"
        with pytest.raises(EnvelopeError):
            Envelope.from_json(json.dumps(data))

    def test_oversized_plaintext_is_refused_at_seal_time(self, alice, bob):
        with pytest.raises(EnvelopeError, match="limit"):
            seal(alice, bob.public, b"x" * (MAX_PLAINTEXT_BYTES + 1))


class TestArmor:
    def test_round_trip(self):
        assert dearmor(armor("payload")) == "payload"

    def test_survives_surrounding_text(self):
        wrapped = "Hello,\n\n" + armor("payload") + "\n\n-- \nSent from my phone\n"
        assert dearmor(wrapped) == "payload"

    def test_missing_block(self):
        with pytest.raises(EnvelopeError, match="no QuMail armoured block"):
            dearmor("just a normal email")

    def test_two_blocks_are_ambiguous_and_refused(self):
        with pytest.raises(EnvelopeError, match="multiple QuMail blocks"):
            dearmor(armor("first") + "\n" + armor("second"))

    def test_non_base64_content_is_rejected(self):
        from qumail.armor import BEGIN_MARKER, END_MARKER

        with pytest.raises(EnvelopeError):
            dearmor(BEGIN_MARKER + "\n!!!!\n" + END_MARKER)

    def test_oversized_body_is_rejected(self):
        with pytest.raises(EnvelopeError):
            dearmor("x" * 2048, max_bytes=1024)

"""Trust store, replay protection, and safe delivery."""

from __future__ import annotations

import time

import pytest

from qumail.contacts import ContactStore
from qumail.crypto.envelope import EnvelopeHeader, new_message_id
from qumail.delivery import deliver
from qumail.errors import QuMailError, ReplayError, TrustError
from qumail.replay import ReplayGuard


class TestContactStore:
    def test_add_and_resolve(self, contacts, alice):
        assert contacts.add(alice.public) is True
        assert contacts.resolve("alice@example.com").fingerprint == alice.fingerprint
        assert contacts.resolve(alice.fingerprint).fingerprint == alice.fingerprint

    def test_fingerprint_lookup_tolerates_spacing(self, contacts, alice):
        assert contacts.add(alice.public) is True
        assert contacts.resolve(alice.public.pretty_fingerprint()) is not None

    def test_reimport_is_idempotent(self, contacts, alice):
        assert contacts.add(alice.public) is True
        assert contacts.add(alice.public) is False
        assert len(contacts) == 1

    def test_persists_across_instances(self, config, alice):
        ContactStore(config.contacts_path).add(alice.public)
        assert len(ContactStore(config.contacts_path)) == 1

    def test_unknown_sender_is_refused(self, contacts, mallory):
        with pytest.raises(TrustError, match="not in the contact store"):
            contacts.require(mallory.fingerprint)

    def test_unknown_reference_is_refused(self, contacts):
        with pytest.raises(TrustError, match="no trusted contact"):
            contacts.resolve("stranger@example.com")

    def test_removal(self, contacts, alice):
        contacts.add(alice.public)
        assert contacts.remove(alice.fingerprint) is True
        assert contacts.remove(alice.fingerprint) is False
        assert len(contacts) == 0

    def test_two_keys_may_claim_one_address(self, contacts, alice):
        """Recorded, but ambiguous: the operator must name the fingerprint."""
        from qumail.crypto.keys import generate_identity

        impostor = generate_identity("alice@example.com")
        contacts.add(alice.public)
        contacts.add(impostor.public)

        with pytest.raises(TrustError, match="specify the fingerprint"):
            contacts.resolve("alice@example.com")
        assert contacts.resolve(alice.fingerprint).fingerprint == alice.fingerprint

    def test_corrupt_store_is_reported(self, config, alice):
        config.contacts_path.parent.mkdir(parents=True, exist_ok=True)
        config.contacts_path.write_text("{not json")
        with pytest.raises(TrustError, match="corrupt"):
            ContactStore(config.contacts_path)

    def test_malformed_entry_is_skipped_not_fatal(self, config, alice):
        store = ContactStore(config.contacts_path)
        store.add(alice.public)

        import json

        data = json.loads(config.contacts_path.read_text())
        data["contacts"].append({"v": 1, "address": "broken@example.com"})
        config.contacts_path.write_text(json.dumps(data))

        reloaded = ContactStore(config.contacts_path)
        assert len(reloaded) == 1


class TestReplayGuard:
    def _guard(self, config, **kwargs):
        options = {"max_age": 3600, "max_skew": 300}
        options.update(kwargs)
        return ReplayGuard(config.state_dir / "replay.json", **options)

    def test_new_message_passes(self, config):
        guard = self._guard(config)
        guard.check_freshness(int(time.time()))
        guard.check_unseen(new_message_id())

    def test_seen_message_is_rejected(self, config):
        guard = self._guard(config)
        message_id = new_message_id()
        guard.record(message_id, int(time.time()))
        with pytest.raises(ReplayError, match="already been processed"):
            guard.check_unseen(message_id)

    def test_record_survives_restart(self, config):
        message_id = new_message_id()
        self._guard(config).record(message_id, int(time.time()))
        with pytest.raises(ReplayError):
            self._guard(config).check_unseen(message_id)

    def test_stale_message_is_rejected(self, config):
        guard = self._guard(config)
        with pytest.raises(ReplayError, match="beyond the"):
            guard.check_freshness(int(time.time()) - 7200)

    def test_future_dated_message_is_rejected(self, config):
        guard = self._guard(config)
        with pytest.raises(ReplayError, match="future"):
            guard.check_freshness(int(time.time()) + 3600)

    def test_small_clock_skew_is_tolerated(self, config):
        guard = self._guard(config, max_skew=300)
        guard.check_freshness(int(time.time()) + 60)

    def test_expired_entries_are_pruned(self, config):
        guard = self._guard(config, max_age=60, max_skew=0)
        guard.record(new_message_id(), int(time.time()) - 5000)
        guard.record(new_message_id(), int(time.time()))
        assert len(guard) == 1

    def test_corrupt_state_does_not_crash(self, config):
        config.state_dir.mkdir(parents=True, exist_ok=True)
        (config.state_dir / "replay.json").write_text("{corrupt")
        assert len(self._guard(config)) == 0


class TestDelivery:
    def _header(self, message_id=None):
        return EnvelopeHeader(
            version=1,
            message_id=message_id or new_message_id(),
            timestamp=int(time.time()),
            sender_fingerprint="a" * 32,
            recipient_fingerprint="b" * 32,
            subject="a subject",
        )

    def test_writes_body_and_metadata(self, config):
        result = deliver(config.output_dir, self._header(), "alice@example.com", b"hi")
        assert result.body_path.read_bytes() == b"hi"
        assert '"sender_address": "alice@example.com"' in result.metadata_path.read_text()

    @pytest.mark.parametrize(
        "evil_id", ["../escape", "..\\escape", "/etc/passwd", "a" * 31, "A" * 32]
    )
    def test_path_traversal_is_impossible(self, config, evil_id):
        header = EnvelopeHeader(
            version=1,
            message_id=evil_id,
            timestamp=int(time.time()),
            sender_fingerprint="a" * 32,
            recipient_fingerprint="b" * 32,
            subject="",
        )
        with pytest.raises(QuMailError):
            deliver(config.output_dir, header, "alice@example.com", b"hi")

    def test_html_output_escapes_the_body(self, config):
        payload = b"<script>alert('xss')</script>"
        header = self._header()
        deliver(
            config.output_dir, header, "<b>alice</b>@example.com", payload,
            write_html=True,
        )
        html_text = (config.output_dir / (header.message_id + ".html")).read_text()

        assert "<script>" not in html_text
        assert "&lt;script&gt;" in html_text
        assert "&lt;b&gt;alice&lt;/b&gt;" in html_text

    def test_output_stays_inside_the_output_directory(self, config):
        header = self._header()
        result = deliver(config.output_dir, header, "alice@example.com", b"hi")
        assert result.body_path.resolve().parent == config.output_dir.resolve()

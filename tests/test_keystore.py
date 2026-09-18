"""Private keys at rest."""

from __future__ import annotations

import json

import pytest

from qumail.crypto import keystore
from qumail.errors import KeystoreError

PASSPHRASE = "correct-horse-battery-staple"


class TestKeystore:
    def test_round_trip(self, tmp_path, alice):
        path = tmp_path / "keystore.json"
        keystore.save(path, alice, PASSPHRASE)
        loaded = keystore.load(path, PASSPHRASE)

        assert loaded.address == alice.address
        assert loaded.fingerprint == alice.fingerprint
        assert loaded.signing_key == alice.signing_key
        assert loaded.kem.x25519 == alice.kem.x25519
        assert loaded.kem.mlkem == alice.kem.mlkem

    def test_private_keys_are_not_on_disk_in_the_clear(self, tmp_path, alice):
        path = tmp_path / "keystore.json"
        keystore.save(path, alice, PASSPHRASE)
        raw = path.read_bytes()

        for secret in (alice.signing_key, alice.kem.x25519, alice.kem.mlkem):
            assert secret not in raw
            # Also check the base64 form, which is how they would be stored.
            import base64

            assert base64.b64encode(secret) not in raw

    def test_wrong_passphrase_fails(self, tmp_path, alice):
        path = tmp_path / "keystore.json"
        keystore.save(path, alice, PASSPHRASE)
        with pytest.raises(KeystoreError, match="wrong passphrase"):
            keystore.load(path, PASSPHRASE + "!")

    def test_weak_passphrase_refused(self, tmp_path, alice):
        with pytest.raises(KeystoreError, match="at least"):
            keystore.save(tmp_path / "keystore.json", alice, "short")

    def test_will_not_silently_overwrite(self, tmp_path, alice, bob):
        path = tmp_path / "keystore.json"
        keystore.save(path, alice, PASSPHRASE)
        with pytest.raises(KeystoreError, match="refusing to overwrite"):
            keystore.save(path, bob, PASSPHRASE)

        keystore.save(path, bob, PASSPHRASE, overwrite=True)
        assert keystore.load(path, PASSPHRASE).fingerprint == bob.fingerprint

    def test_missing_file_gives_an_actionable_error(self, tmp_path):
        with pytest.raises(KeystoreError, match="keygen"):
            keystore.load(tmp_path / "nope.json", PASSPHRASE)

    def test_tampered_ciphertext_is_detected(self, tmp_path, alice):
        path = tmp_path / "keystore.json"
        keystore.save(path, alice, PASSPHRASE)

        data = json.loads(path.read_text())
        import base64

        blob = bytearray(base64.b64decode(data["ct"]))
        blob[0] ^= 0x01
        data["ct"] = base64.b64encode(bytes(blob)).decode()
        path.write_text(json.dumps(data))

        with pytest.raises(KeystoreError):
            keystore.load(path, PASSPHRASE)

    def test_tampered_header_is_detected(self, tmp_path, alice):
        """The plaintext metadata is authenticated as associated data."""
        path = tmp_path / "keystore.json"
        keystore.save(path, alice, PASSPHRASE)

        data = json.loads(path.read_text())
        data["address"] = "attacker@example.com"
        path.write_text(json.dumps(data))

        with pytest.raises(KeystoreError):
            keystore.load(path, PASSPHRASE)

    def test_absurd_scrypt_cost_is_refused(self, tmp_path, alice):
        """A hostile file must not be able to demand terabytes of memory."""
        path = tmp_path / "keystore.json"
        keystore.save(path, alice, PASSPHRASE)

        data = json.loads(path.read_text())
        data["kdf"]["n"] = 2 ** 30
        path.write_text(json.dumps(data))

        with pytest.raises(KeystoreError, match="cost parameters"):
            keystore.load(path, PASSPHRASE)

    def test_oversized_file_is_refused(self, tmp_path, alice):
        path = tmp_path / "keystore.json"
        keystore.save(path, alice, PASSPHRASE)
        path.write_text("x" * (keystore.MAX_KEYSTORE_BYTES + 1))
        with pytest.raises(KeystoreError, match="implausibly large"):
            keystore.load(path, PASSPHRASE)

    def test_corrupt_json_is_refused(self, tmp_path, alice):
        path = tmp_path / "keystore.json"
        keystore.save(path, alice, PASSPHRASE)
        path.write_text("{not json")
        with pytest.raises(KeystoreError, match="corrupt"):
            keystore.load(path, PASSPHRASE)

    def test_each_save_uses_a_fresh_salt(self, tmp_path, alice):
        first, second = tmp_path / "a.json", tmp_path / "b.json"
        keystore.save(first, alice, PASSPHRASE)
        keystore.save(second, alice, PASSPHRASE)

        salt_a = json.loads(first.read_text())["kdf"]["salt"]
        salt_b = json.loads(second.read_text())["kdf"]["salt"]
        assert salt_a != salt_b
        # Same identity, same passphrase, different ciphertext.
        assert json.loads(first.read_text())["ct"] != json.loads(second.read_text())["ct"]

"""Primitives: the hybrid KEM, the AEAD, and identity fingerprints."""

from __future__ import annotations

import pytest

from qumail.crypto.aead import decrypt, encrypt, generate_nonce
from qumail.crypto.kdf import digest, hkdf
from qumail.crypto.kem import (
    MLKEM_CIPHERTEXT_SIZE,
    MLKEM_PUBLIC_SIZE,
    X25519_PUBLIC_SIZE,
    KemCiphertext,
    decapsulate,
    encapsulate,
    generate_keypair,
)
from qumail.crypto.keys import PublicIdentity
from qumail.errors import CryptoError, EnvelopeError


class TestHybridKem:
    def test_both_sides_agree(self):
        public, private = generate_keypair()
        ciphertext, sent = encapsulate(public, b"context")
        assert decapsulate(private, public, ciphertext, b"context") == sent
        assert len(sent) == 32

    def test_key_sizes_are_the_real_ml_kem_768_sizes(self):
        public, _ = generate_keypair()
        assert len(public.x25519) == X25519_PUBLIC_SIZE == 32
        assert len(public.mlkem) == MLKEM_PUBLIC_SIZE == 1184

        ciphertext, _ = encapsulate(public, b"c")
        assert len(ciphertext.mlkem) == MLKEM_CIPHERTEXT_SIZE == 1088

    def test_every_encapsulation_is_fresh(self):
        public, _ = generate_keypair()
        first, key_a = encapsulate(public, b"context")
        second, key_b = encapsulate(public, b"context")
        assert key_a != key_b
        assert first.x25519_ephemeral != second.x25519_ephemeral
        assert first.mlkem != second.mlkem

    def test_different_context_yields_a_different_key(self):
        public, private = generate_keypair()
        ciphertext, sent = encapsulate(public, b"context-a")
        assert decapsulate(private, public, ciphertext, b"context-b") != sent

    def test_wrong_recipient_cannot_recover_the_key(self):
        public, _ = generate_keypair()
        _, other_private = generate_keypair()
        ciphertext, sent = encapsulate(public, b"context")
        # ML-KEM rejects implicitly rather than raising, so the check is that
        # the derived key simply does not match.
        assert decapsulate(other_private, public, ciphertext, b"context") != sent

    def test_swapping_the_pq_half_breaks_the_key(self):
        """Neither half alone determines the key."""
        public, private = generate_keypair()
        first, key_a = encapsulate(public, b"context")
        second, _ = encapsulate(public, b"context")

        spliced = KemCiphertext(
            x25519_ephemeral=first.x25519_ephemeral, mlkem=second.mlkem
        )
        assert decapsulate(private, public, spliced, b"context") != key_a

    def test_malformed_sizes_are_rejected(self):
        with pytest.raises(ValueError):
            KemCiphertext(x25519_ephemeral=b"short", mlkem=b"\x00" * MLKEM_CIPHERTEXT_SIZE)


class TestAead:
    def test_round_trip(self):
        key = b"k" * 32
        nonce, ciphertext = encrypt(key, b"secret", b"header")
        assert decrypt(key, nonce, ciphertext, b"header") == b"secret"

    def test_modified_ciphertext_is_rejected(self):
        key = b"k" * 32
        nonce, ciphertext = encrypt(key, b"secret", b"header")
        broken = bytearray(ciphertext)
        broken[0] ^= 0x01
        with pytest.raises(CryptoError):
            decrypt(key, nonce, bytes(broken), b"header")

    def test_modified_associated_data_is_rejected(self):
        key = b"k" * 32
        nonce, ciphertext = encrypt(key, b"secret", b"header")
        with pytest.raises(CryptoError):
            decrypt(key, nonce, ciphertext, b"other header")

    def test_associated_data_is_mandatory(self):
        with pytest.raises(ValueError):
            encrypt(b"k" * 32, b"secret", b"")

    def test_nonces_do_not_repeat(self):
        assert len({generate_nonce() for _ in range(200)}) == 200

    def test_error_message_reveals_nothing(self):
        key = b"k" * 32
        nonce, ciphertext = encrypt(key, b"secret", b"header")
        with pytest.raises(CryptoError) as info:
            decrypt(key, nonce, ciphertext, b"wrong")
        assert str(info.value) == "message rejected"


class TestKdf:
    def test_purpose_separates_keys(self):
        ikm = b"i" * 32
        assert hkdf(ikm, purpose=b"a") != hkdf(ikm, purpose=b"b")

    def test_context_separates_keys(self):
        ikm = b"i" * 32
        assert hkdf(ikm, purpose=b"a", context=b"x") != hkdf(
            ikm, purpose=b"a", context=b"y"
        )

    def test_purpose_is_required(self):
        with pytest.raises(ValueError):
            hkdf(b"i" * 32, purpose=b"")

    def test_digest_is_unambiguous(self):
        """Length prefixing means chunk boundaries matter."""
        assert digest(b"ab", b"c") != digest(b"a", b"bc")


class TestIdentity:
    def test_fingerprint_is_stable_and_reproducible(self, alice):
        assert alice.fingerprint == alice.public.fingerprint
        rebuilt = PublicIdentity.from_json(alice.public.to_json())
        assert rebuilt.fingerprint == alice.fingerprint

    def test_fingerprint_covers_every_key(self, alice, bob):
        """Swapping any single key changes the fingerprint."""
        base = alice.public
        swapped_signing = PublicIdentity(
            address=base.address, signing_key=bob.public.signing_key, kem=base.kem
        )
        swapped_kem = PublicIdentity(
            address=base.address, signing_key=base.signing_key, kem=bob.public.kem
        )
        renamed = PublicIdentity(
            address="eve@example.com", signing_key=base.signing_key, kem=base.kem
        )
        assert len({
            base.fingerprint,
            swapped_signing.fingerprint,
            swapped_kem.fingerprint,
            renamed.fingerprint,
        }) == 4

    def test_bundle_with_edited_key_is_refused(self, alice, bob):
        """A claimed fingerprint that disagrees with the keys is a red flag."""
        import base64

        data = alice.public.to_dict()
        data["sig_pk"] = base64.b64encode(bob.public.signing_key).decode()
        with pytest.raises(EnvelopeError, match="fingerprint does not match"):
            PublicIdentity.from_dict(data)

    def test_signatures_verify(self, alice, bob):
        signature = alice.sign(b"message")
        alice.public.verify(b"message", signature)
        with pytest.raises(CryptoError):
            bob.public.verify(b"message", signature)
        with pytest.raises(CryptoError):
            alice.public.verify(b"other message", signature)

    def test_truncated_signature_is_rejected(self, alice):
        with pytest.raises(CryptoError):
            alice.public.verify(b"message", alice.sign(b"message")[:-1])

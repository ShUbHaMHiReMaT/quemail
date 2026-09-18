"""Cryptographic primitives for QuMail.

Layout:
    kdf       -- HKDF-SHA256 wrapper with mandatory domain separation
    aead      -- AES-256-GCM with mandatory associated data
    kem       -- hybrid X25519 + ML-KEM-768 key encapsulation
    keys      -- identity key bundles and fingerprints
    keystore  -- passphrase-encrypted private key storage
    envelope  -- the on-the-wire message format
"""

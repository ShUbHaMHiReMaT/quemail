# kyber.py (Hackathon Demo Stub - FIXED)
# A simple, consistent Kyber-like KEM stub for demo use.
# keygen() -> (pk, sk) where sk = sha256(pk)
# enc(pk) -> (ct, shared_secret) where shared_secret = sha256(ct + sha256(pk))
# dec(ct, sk) -> shared_secret = sha256(ct + sk)
# This ensures enc() and dec() derive the same shared_secret deterministically.

import os
import hashlib

class Kyber768:
    pk_size = 1184
    ct_size = 1088

    @staticmethod
    def keygen():
        """
        Generate a fake Kyber768 keypair.
        pk is random; sk is sha256(pk) to allow enc/dec to derive same shared secret.
        """
        pk = os.urandom(Kyber768.pk_size)
        sk = hashlib.sha256(pk).digest()
        return pk, sk

    @staticmethod
    def enc(pk):
        """
        Encapsulate a new shared secret with the given public key.
        Returns (ciphertext, shared_secret).
        Deterministic shared_secret = sha256(ct + sha256(pk))
        """
        ct = os.urandom(Kyber768.ct_size)
        pk_hash = hashlib.sha256(pk).digest()
        shared_secret = hashlib.sha256(ct + pk_hash).digest()
        return ct, shared_secret

    @staticmethod
    def dec(ct, sk):
        """
        Decapsulate a shared secret from ciphertext using secret key.
        Returns shared_secret = sha256(ct + sk)
        """
        shared_secret = hashlib.sha256(ct + sk).digest()
        return shared_secret

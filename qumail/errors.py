"""Exception hierarchy.

Every failure a remote party can trigger is a `QuMailError`, so the receive
loop can drop a bad message without taking down the daemon. Anything else is a
bug and is allowed to propagate.
"""


class QuMailError(Exception):
    """Base class for all expected QuMail failures."""


class ConfigError(QuMailError):
    """Configuration is missing, malformed, or unsafe."""


class KeystoreError(QuMailError):
    """Keystore is missing, corrupt, or the passphrase is wrong."""


class TrustError(QuMailError):
    """Sender is unknown or not trusted for this operation."""


class EnvelopeError(QuMailError):
    """Envelope is malformed, oversized, or fails validation."""


class CryptoError(QuMailError):
    """Decapsulation, decryption, or signature verification failed.

    Deliberately coarse: a caller cannot tell *which* check failed, which keeps
    this from becoming a decryption oracle.
    """


class ReplayError(QuMailError):
    """Envelope is stale or has been processed before."""


class TransportError(QuMailError):
    """SMTP/IMAP connection or protocol failure."""

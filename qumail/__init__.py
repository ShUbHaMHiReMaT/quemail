"""QuMail -- post-quantum hybrid end-to-end encrypted email over SMTP/IMAP."""

__version__ = "1.0.0"

# Wire-format version. Bump on any change to the envelope layout or key
# derivation; receivers reject envelopes that do not carry this exact value.
PROTOCOL_VERSION = 1

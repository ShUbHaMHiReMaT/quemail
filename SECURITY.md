# Security design

## Threat model

**Defended against**

| Adversary | Capability | Why it fails |
|---|---|---|
| The mail provider | Reads and edits every stored message | Sees only ciphertext; any edit breaks the AEAD tag |
| A network attacker | Intercepts and rewrites traffic | TLS with certificate and hostname verification, no plaintext fallback |
| A future quantum adversary | Records traffic now, breaks it later | ML-KEM-768 protects the key alongside X25519 |
| An impersonator | Sends mail claiming to be a known contact | Ed25519 signature checked against the key already pinned to that fingerprint |
| A replay attacker | Re-sends a genuine captured message | Freshness window plus persistent seen-id store |
| A local user on the same host | Reads files on disk | Keystore encrypted with scrypt; keys and output are mode 600 |

**Not defended against**

- **Traffic analysis.** Sender, recipient, timing and approximate size are
  visible to the provider. Only the body and subject are encrypted.
- **Endpoint compromise.** Malware on either machine, or a keylogger capturing
  the passphrase, defeats everything below.
- **Compromise of the long-term keystore.** An attacker with the keystore and
  the passphrase can read recorded past traffic. Per-message ephemeral keys do
  not help once the static decapsulation key is known.
- **A wrong key accepted at first contact.** Keys are adopted on first use
  (see below), so an attacker who can intercept mail at that exact moment can
  substitute their own. Verify the fingerprint out of band, or run with
  `--no-learn` and import keys yourself.

- **Whoever hosts the service, if you host it.** See *Hosted deployments*.

## Cryptographic construction

```
KEM      hybrid: X25519 (ephemeral-static) + ML-KEM-768 (FIPS 203)
KDF      HKDF-SHA256, salt = "qumail/v1/<purpose>", info = transcript
AEAD     AES-256-GCM, 96-bit random nonce, header as associated data
SIGN     Ed25519 over header + KEM ciphertext + nonce + ciphertext
KEYSTORE scrypt (n=2^16, r=8, p=1) -> AES-256-GCM
```

Per message:

1. A fresh X25519 ephemeral key and a fresh ML-KEM encapsulation produce two
   independent shared secrets.
2. Both are concatenated and passed through HKDF-SHA256. The `info` is a
   transcript hash covering **both** ephemeral and static public keys, **both**
   ciphertexts, and the full envelope header (version, message id, timestamp,
   subject, and both parties' fingerprints).
3. AES-256-GCM encrypts the body with the canonical header as associated data.
4. Ed25519 signs the header and the ciphertext together.

### Why the key derivation binds so much

Binding the transcript is what stops keys and ciphertexts being moved between
contexts. Concretely:

- Editing any header field — subject, timestamp, message id, either
  fingerprint — changes the associated data *and* the KEM context, so the body
  fails to decrypt. Headers cannot be rewritten in transit.
- Splicing the X25519 half of one message onto the ML-KEM half of another
  yields an unrelated key.
- The sender's fingerprint sits inside the KEM context. This closes the
  standard weakness of encrypt-then-sign: an attacker who strips Alice's
  signature, relabels the message as their own and re-signs it produces a
  *valid signature* over a message whose key no longer derives. Authorship is
  bound to the content, not merely asserted next to it. Tested in
  `tests/test_envelope.py::TestImpersonation::test_signature_stripping_and_resigning_fails`.

### Failure handling

Decryption failures raise one coarse error, `CryptoError("message rejected")`,
regardless of whether the signature, the KEM or the AEAD tag failed. A precise
error would be a decryption oracle. ML-KEM's implicit rejection is relied on
as designed: a malformed ciphertext yields an unpredictable key rather than an
error, and the failure surfaces at the AEAD.

## Trust on first use

The sender's public key bundle travels inside every envelope. A receiver that
does not yet know that fingerprint adopts the attached key and stores it.

This is safe to do without weakening the cryptography, because the bundle is
not trusted on its own merits: the envelope header carries the sender's
fingerprint, which is a SHA-256 commitment over the whole bundle (address and
all three public keys), and that fingerprint is both signed and bound into the
KEM derivation. A bundle that has been swapped or edited therefore fails to
match before any of its keys is used. What is taken on faith is *whose* key it
is -- never whether the key is intact.

The resulting properties:

| | Guarantee |
|---|---|
| First message from a new fingerprint | Taken on faith. An active attacker present at that moment can substitute a key. |
| Every later message | Verified against the stored key. Nothing arriving by email can displace a key already held. |
| A stored key vs. an attached one | The stored key always wins, so an imported and verified contact can never be downgraded. |
| Detection | The fingerprint changes, so a substitution appears as a *new* contact rather than a silent swap. |

`qumail receive --no-learn` disables adoption entirely: senders must have been
imported in advance, which restores verify-before-first-message at the cost of
the manual exchange.

### Contact requests

An invitation is a plaintext email carrying a public key. Nothing in it is
secret -- a public key is meant to be seen -- but it is also unauthenticated,
so it is filed as *pending* and never imported on its own. Anyone can email
anyone a key claiming any address; the fingerprint shown beside it is what the
recipient checks, through some channel other than the mailbox in question.

The pending list is bounded at 100 entries and is stored under filenames
derived from validated 32-character hex fingerprints, so a request cannot
steer a filesystem path or exhaust the disk. A request whose fingerprint is
already a trusted contact is discarded rather than queued.

## Hosted deployments

Running the web inbox on a server, such as Render, moves the decryption
boundary. That host needs the keystore and its passphrase, so:

- Messages remain encrypted against the mail provider, the network, and every
  third party. The post-quantum guarantees against *harvest now, decrypt
  later* are unchanged, because what is archived at the provider is still
  ciphertext.
- Messages are **not** encrypted against the host. Whoever controls that
  machine, or compromises it, can read plaintext and sign messages as you.

This is the same trade every webmail client makes, and it is a legitimate one
-- but it should be a decision, not a surprise. For a threat model where
nobody but you may read the plaintext, run `qumail web` bound to 127.0.0.1 on
your own machine.

When hosting anyway:

- The web inbox refuses to start without `QUMAIL_WEB_PASSWORD_HASH`; the
  password is stored only as an scrypt hash.
- Sessions are HMAC-signed tokens in a cookie marked HttpOnly, SameSite=Strict
  and Secure. Forms carry a CSRF token derived from the session.
- The Content-Security-Policy is `default-src 'none'` with script and style
  from `'self'` only -- no inline script, no third-party origins, no framing.
- Five failed logins lock a client out for five minutes.
- Responses carry `Cache-Control: no-store`: decrypted mail must not sit in a
  proxy or browser cache.
- Routing is an explicit table with no static directory, so no filesystem path
  is ever derived from a URL.
- Give the service a persistent disk. Without one, the learned contact keys
  and the replay store are wiped on every restart, which silently disables
  both key pinning and replay protection.

## Receive pipeline

Every inbound message passes all seven checks, in this order:

1. body contains exactly one armoured block (two would be ambiguous)
2. envelope parses within size limits and the version matches
3. it is addressed to this keystore's fingerprint
4. the sender's fingerprint is in the contact store, or the bundle attached to
   the message matches that fingerprint and is adopted on first contact
5. the Ed25519 signature verifies under that contact's key
6. the KEM and AEAD verify
7. the timestamp is fresh and the message id has not been seen

Steps 3 and 7 run before any asymmetric work, so stale or replayed mail cannot
be used to burn CPU. A failure at any step drops that message and the loop
continues: one hostile sender cannot stop the daemon from processing everyone
else's mail.

Untrusted senders are *deferred* rather than discarded — the message stays
unread, so importing the contact later makes it readable on the next poll.
Permanently invalid messages are flagged read so they are not re-downloaded
forever.

The read flag is an efficiency filter, never a security control: what stops a
message being processed twice is the replay store, which is why
`receive --include-read` can widen the search without weakening anything. The
flag cannot be trusted in either direction — any mail client sharing the
mailbox can set or clear it, and Gmail sets it automatically on mail you send
to yourself.

## Input validation

Everything on the wire is attacker-controlled and treated as such.

- **Message ids** must match `^[0-9a-f]{32}$`. They end up in an output
  filename, so anything looser would let a remote sender steer writes with
  `../` or a drive prefix. The path is then re-checked against the output
  directory with `Path.relative_to`.
- **Size ceilings** are applied before parsing: 8 MiB per envelope, 4 MiB per
  plaintext, 1 MiB per mail body by default, 64 KiB per keystore, 4 MiB per
  contact store.
- **Base64 fields** are decoded with `validate=True` and checked for exact
  expected lengths.
- **scrypt parameters** read from a keystore file are bounded, so a hostile
  file cannot demand terabytes of memory.
- **HTML output** escapes every interpolated value, including the sender
  address and subject.
- **Email addresses** are rejected if they contain CR, LF or tab — the classic
  header-injection vector.

## Transport

Both `smtplib.starttls()` and `imaplib.IMAP4_SSL()` fall back to
`ssl._create_stdlib_context()` when no context is supplied, which sets
`check_hostname=False` and `verify_mode=CERT_NONE` — **no certificate
validation at all**. QuMail therefore builds every context through
`transport/tls.py:secure_context()`, which requires certificate and hostname
verification and TLS 1.2 or better, and asserts those properties rather than
assuming them.

If a server does not offer STARTTLS, the send fails. There is no plaintext
fallback, because falling back is exactly what a stripping attacker wants.

## Key and credential handling

- Private keys are never written unencrypted. The keystore is AES-256-GCM
  under an scrypt-derived key; the plaintext metadata beside it (address,
  fingerprint, KDF parameters) is authenticated as associated data.
- Loading a keystore that is group- or world-readable is refused outright,
  since the key may already be compromised.
- Passphrases come from `QUMAIL_KEYSTORE_PASSPHRASE` or an interactive prompt
  that never echoes. Minimum 12 characters.
- No credential appears in source, in the container image, or in a log. A
  redacting filter runs over every log record — including dependency
  tracebacks — scrubbing anything shaped like a password, a long hex run or a
  long base64 run.
- `keygen` refuses to overwrite an existing keystore without `--force`.

## Known limitations

- **`kyber-py` is not constant-time.** It is a pure-Python reference
  implementation, chosen for portability and auditability over speed. On a
  machine where an attacker can run code alongside the receiver and measure it
  precisely, a timing side channel on the decapsulation key is conceivable.
  The X25519 half, via `cryptography`/OpenSSL, is constant-time, so the hybrid
  key remains protected by that half. For a high-assurance deployment, swap in
  liboqs.
- **Python cannot reliably zeroise memory.** Key material may persist in the
  heap after use and can reach a swap file or core dump. Disable swap or use
  an encrypted swap device for sensitive deployments.
- **No forward secrecy against static key compromise**, as described in the
  threat model.
- **The protocol version is pinned.** Version 1 envelopes are the only ones
  accepted; there is no negotiation and therefore no downgrade to negotiate.

## Reporting a vulnerability

Open a private security advisory on the repository rather than a public issue.

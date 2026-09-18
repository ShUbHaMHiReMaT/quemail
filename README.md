# QuMail

End-to-end encrypted email over ordinary SMTP and IMAP, using a **post-quantum
hybrid** key exchange. Works with any mail account you already have — Gmail,
Outlook, a company server. The provider carries the ciphertext and never sees
the content.

```
   sender                                                    recipient
     |                                                            |
     |  X25519 + ML-KEM-768  ->  HKDF-SHA256  ->  AES-256-GCM      |
     |  Ed25519 signature over the sealed result                   |
     |                                                            |
     +----------- ordinary SMTP  ~~>  mailbox  ~~>  IMAP ----------+
                        (provider sees only ciphertext)
```

## Why hybrid

Two independent key exchanges run for every message and both shared secrets
feed one HKDF. The message key stays secret unless **both** are broken:

- **X25519** — twenty years of classical scrutiny, protects against a flaw in
  the newer lattice scheme or its implementation.
- **ML-KEM-768** (FIPS 203, formerly Kyber) — protects against *harvest now,
  decrypt later*: traffic recorded today and broken by a quantum computer
  years from now. Email is archived for decades, so this is not hypothetical.

This is the construction NIST and the IETF recommend for the migration period.
Neither primitive alone is trusted.

## Install

Requires Python 3.9 or newer.

```bash
python -m venv venv
venv/bin/activate            # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

## Quick start

Both parties do this once:

```bash
# 1. Create your identity. Choose a strong passphrase -- it protects your
#    private keys at rest, and there is no recovery if you lose it.
qumail keygen --address you@example.com

# 2. Export your public identity and send the file to the other person.
qumail export-identity --out me.qumail-id.json
```

Then exchange and **verify** each other's keys:

```bash
# 3. Import what they sent you.
qumail import-contact them.qumail-id.json

# 4. Read the fingerprint back to them over a phone call, in person, or any
#    channel an attacker cannot rewrite -- NOT the mailbox you are securing.
#    Once verified, pin it so a future key swap is refused:
qumail import-contact them.qumail-id.json \
    --expect-fingerprint "83bc 5271 605d c140 b9e8 35c2 913b 1a9a"
```

This step is the whole security model. A signature only proves something once
you know whose key you are checking against; anyone can generate a key
claiming any address. QuMail will not decrypt mail from a key you have not
imported.

Configure mail access:

```bash
cp .env.example .env     # then fill it in
chmod 600 .env           # Linux/macOS
qumail doctor            # verify everything before going live
```

Send and receive:

```bash
qumail send --to them@example.com --subject "lunch" --message "1pm?"
qumail send --to them@example.com --file report.txt

qumail receive --once     # poll once and exit
qumail receive            # run continuously
```

Decrypted messages land in `QUMAIL_OUTPUT_DIR` (default `./inbox/`) as
`<message-id>.txt` with a `.json` sidecar naming the verified sender.

### Sending to yourself

By default the receiver only looks at unread mail, which keeps each poll
proportional to what has newly arrived. Gmail marks a message you send to
your own address as read on delivery, so it will never appear unread:

```bash
qumail receive --once --include-read
```

Re-processing is prevented by the replay store rather than by the read flag,
so widening the search is safe — it only costs bandwidth as the mailbox grows.
Leave the flag off for a long-running daemon receiving mail from other people.

## Commands

| Command | Purpose |
|---|---|
| `qumail keygen --address ADDR` | create an identity and encrypted keystore |
| `qumail export-identity [--out FILE]` | write your public identity to share |
| `qumail import-contact FILE [--expect-fingerprint FP]` | trust someone's key |
| `qumail contacts [--json]` | list trusted contacts |
| `qumail remove-contact FP` | stop trusting a key |
| `qumail send --to ADDR` | encrypt, sign and send |
| `qumail receive [--once] [--html] [--include-read]` | poll, verify, decrypt |
| `qumail doctor` | check config, keystore and contacts |

## Configuration

Every setting is an environment variable; `.env` in the working directory is
read automatically, and real environment variables always take precedence. See
[.env.example](.env.example) for the full list. There are **no default
credentials** — a missing setting stops the process.

| Variable | Default | Meaning |
|---|---|---|
| `QUMAIL_KEYSTORE_PASSPHRASE` | *(prompts)* | unlocks the keystore; required for unattended runs |
| `QUMAIL_SMTP_HOST` / `_PORT` / `_USERNAME` / `_PASSWORD` | — | outbound mail |
| `QUMAIL_SMTP_SECURITY` | `starttls` | `starttls` or `ssl`; plaintext is not an option |
| `QUMAIL_IMAP_HOST` / `_PORT` / `_USERNAME` / `_PASSWORD` | — | inbound mail |
| `QUMAIL_POLL_INTERVAL` | `30` | seconds between IMAP polls |
| `QUMAIL_MAX_MESSAGE_AGE` | `604800` | reject envelopes older than this (seconds) |
| `QUMAIL_MAX_CLOCK_SKEW` | `300` | tolerance for a fast sender clock |
| `QUMAIL_HOME` | `~/.qumail` | keystore, contacts and state |
| `QUMAIL_OUTPUT_DIR` | `./inbox` | where decrypted messages are written |

With Gmail you need an [app password](https://myaccount.google.com/apppasswords);
your normal password will not work over SMTP or IMAP.

## Deployment

**Docker** — no keys or secrets in the image; mount the keystore, inject the
rest:

```bash
qumail keygen --address you@example.com    # on the host first
docker compose up -d
docker compose logs -f
```

**systemd** — see [deploy/qumail-receiver.service](deploy/qumail-receiver.service),
which runs the daemon unprivileged under a strict sandbox.

Both set `QUMAIL_LOG_FORMAT=json` for log aggregation. The receiver handles
`SIGTERM` by finishing the message in flight and exiting cleanly.

## Security

The design, the threat model and what QuMail deliberately does *not* protect
are in [SECURITY.md](SECURITY.md). In short:

- ML-KEM-768 + X25519, HKDF-SHA256, AES-256-GCM, Ed25519
- private keys encrypted at rest with scrypt (n=2¹⁶)
- TLS with certificate **and** hostname verification on every connection
- sender authentication bound into the key derivation, so a stripped-and-
  re-signed message will not decrypt
- replay protection: freshness window plus a persistent seen-id store
- no credentials in the source, in the image, or in the logs

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

130 tests covering the primitives, the wire format, the keystore, the trust
store, replay protection and the receive pipeline — including the attacks each
is there to stop: tampering, impersonation, signature stripping, replay, path
traversal and HTML injection.

## Benchmarks

```bash
python tools/benchmark.py --runs 100
python tools/plot_benchmark.py
```

Compares ML-KEM-768, X25519, ECDH P-384 and the shipped hybrid on latency and
wire cost. Note that `kyber-py` is a pure-Python implementation chosen for
portability and auditability — its absolute timings are far slower than an
optimised C library such as liboqs, and should not be quoted as ML-KEM's real
cost.

## Project layout

```
qumail/
  crypto/       kdf, aead, kem, keys, keystore, envelope
  transport/    tls, smtp, imap
  cli.py        command line interface
  config.py     environment-driven configuration
  contacts.py   trust store
  replay.py     freshness and replay protection
  receiver.py   the receive pipeline
  delivery.py   safe output writing
tests/          the test suite
tools/          benchmarking
deploy/         systemd unit
```

## Limitations

- **Metadata is not hidden.** Your provider still sees who mailed whom and
  when. Only the body and the subject you pass to `--subject` are encrypted.
- **Key exchange is manual.** There is no directory and no trust-on-first-use;
  you verify fingerprints yourself. That is a deliberate trade of convenience
  for a trust model you can actually reason about.
- **No forward secrecy across a key compromise.** Each message uses a fresh
  ephemeral key, but an attacker who takes your long-term keystore *and*
  recorded your ciphertexts can read the past. Rotate keys periodically.
- `kyber-py` is a reference implementation; it is not constant-time. See
  SECURITY.md for when that matters.

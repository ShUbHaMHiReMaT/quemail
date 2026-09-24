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

```bash
# 1. Create your identity. Choose a strong passphrase -- it protects your
#    private keys at rest, and there is no recovery if you lose it.
qumail keygen --address you@example.com

# 2. Point QuMail at your mailbox.
cp .env.example .env     # fill in SMTP/IMAP and an app password
chmod 600 .env           # Linux/macOS

# 3. Set a password for the browser inbox.
qumail set-web-password  # paste the two values it prints into .env

# 4. Check everything before going live.
qumail doctor
```

Then open the inbox and start writing:

```bash
qumail web               # http://127.0.0.1:8000
```

That is the whole setup. There are no key files to swap: your public key rides
along with every message you send, and the other side adopts it automatically
on first contact. See [First contact is automatic](#first-contact-is-automatic)
for exactly what that does and does not guarantee.

### Or from the command line

```bash
qumail send --to them@example.com --subject "lunch" --message "1pm?"
qumail send --to them@example.com --file report.txt

qumail receive --once    # poll once and exit
qumail receive           # run continuously
```

Decrypted messages land in `QUMAIL_OUTPUT_DIR` (default `./inbox/`) as
`<message-id>.txt` with a `.json` sidecar naming the verified sender.

### Reaching someone for the first time

You cannot encrypt to a key you do not have, so the first exchange has to start
with a public key travelling in the clear -- which is safe, because a public
key is meant to be seen.

1. **Add a contact** in the web inbox (or `qumail invite --to them@example.com`)
   sends them a plaintext contact request carrying your public key and its
   fingerprint.
2. They accept it in their own QuMail, having checked the fingerprint.
3. Their reply is encrypted and carries *their* key, which your side adopts
   automatically.

From then on both directions are sealed and nothing more is exchanged by hand.

### Verifying a contact

Automatic key exchange is convenient, not infallible. To be certain who you
are talking to, compare fingerprints over a channel an attacker cannot rewrite
-- a phone call, in person, anything that is not the mailbox you are securing:

```bash
qumail contacts                          # shows every fingerprint you hold
qumail export-identity --out me.qumail-id.json

# The strict path: import their key yourself and assert the fingerprint.
qumail import-contact them.qumail-id.json     --expect-fingerprint "83bc 5271 605d c140 b9e8 35c2 913b 1a9a"
```

### First contact is automatic

Your public key travels with every message you send. The first time someone
receives mail from you, their QuMail adopts that key and pins it to your
fingerprint; from then on it is the key they use. Neither of you exchanges a
file.

What this does and does not buy you:

- A message from a fingerprint you have seen before is verified against the
  key you already hold. Nothing arriving by email can replace it.
- The very first message from a new person is taken on faith. Someone able to
  intercept mail at exactly that moment could substitute their own key.
- The fingerprint is shown in the UI and in `qumail contacts`, so you can
  confirm it by phone whenever you like -- before or after the fact.

This is the model Signal and WhatsApp use. For a stricter posture, exchange
identity files first and run `qumail receive --no-learn`, which refuses any
sender you have not explicitly imported.

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
| `qumail invite --to ADDR` | email someone your public key |
| `qumail pending [--accept FP] [--dismiss FP]` | contact requests awaiting a decision |
| `qumail web` | run the browser inbox |
| `qumail set-web-password` | generate the web inbox login credentials |
| `qumail doctor` | check config, keystore and contacts |

## The web inbox

A browser UI instead of the command line: conversations on the left, the
thread in the middle, a compose box underneath. It polls in the background, so
new mail appears without you running anything.

```bash
qumail set-web-password        # prints two values for your .env
qumail web                     # http://127.0.0.1:8000
```

Contacts are managed from the same page. **Add a contact** emails someone your
public key; when they accept and reply, their key arrives with the reply and
you can write to them encrypted. Keys that arrive from other people appear as
**Contact requests** with their fingerprint and an Accept button -- never
imported silently, because an identity block is only a claim until a person
checks it. You can also paste a key directly, or copy your own out to share.

It will not start without a password, because the pages it serves are
decrypted mail. Sessions are signed cookies (HttpOnly, SameSite=Strict,
Secure behind HTTPS), forms carry CSRF tokens, the Content-Security-Policy
forbids inline and third-party script, and repeated failed logins lock the
client out for five minutes.

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

**Render** — [render.yaml](render.yaml) is a ready blueprint. Point Render at
the repo as a Blueprint, fill in the prompted secrets, and deploy. Keep the
disk: without it the learned contact keys and replay state are wiped on every
restart.

**systemd** — see [deploy/qumail-receiver.service](deploy/qumail-receiver.service),
which runs the daemon unprivileged under a strict sandbox.

> **Hosting it changes the threat model.** A server that decrypts your mail
> holds your private key, so whoever runs that machine can read everything.
> Messages stay encrypted against your mail provider, the network and any
> other third party -- but not against the host. That is the same trade every
> webmail service makes. If nobody but you may ever see the plaintext, run
> `qumail web` locally on 127.0.0.1 instead. See [SECURITY.md](SECURITY.md).

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

"""Command line interface.

    qumail keygen --address you@example.com
    qumail export-identity --out you.qumail-id.json
    qumail import-contact them.qumail-id.json
    qumail contacts
    qumail send --to them@example.com --subject "hi" --message "text"
    qumail receive [--once]
    qumail doctor
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from . import __version__
from .config import Config, bootstrap_keystore, get_passphrase, load_config
from .contacts import ContactStore
from .crypto import keystore
from .crypto.envelope import MAX_PLAINTEXT_BYTES, seal
from .crypto.keys import PrivateIdentity, PublicIdentity, generate_identity
from .errors import ConfigError, QuMailError
from .fsutil import atomic_write_text, ensure_private_dir
from .logging_setup import configure_logging, get_logger
from .receiver import Receiver
from .transport.smtp import send as smtp_send

log = get_logger("qumail")


def _unlock(config: Config) -> PrivateIdentity:
    return keystore.load(config.keystore_path, get_passphrase())


def _print_identity(identity: PublicIdentity, *, heading: str) -> None:
    print(heading)
    print("  address:     %s" % identity.address)
    print("  fingerprint: %s" % identity.pretty_fingerprint())


# ---------------------------------------------------------------- commands


def cmd_keygen(args: argparse.Namespace, config: Config) -> int:
    ensure_private_dir(config.keystore_path.parent)
    identity = generate_identity(args.address)
    keystore.save(
        config.keystore_path,
        identity,
        get_passphrase(confirm=True),
        overwrite=args.force,
    )
    _print_identity(identity.public, heading="Generated identity:")
    print()
    print("Keystore: %s" % config.keystore_path)
    print(
        "Back this file up. Without it -- and its passphrase -- messages sent to\n"
        "you cannot be decrypted by anyone, including you."
    )
    print()
    print("Share your public identity with:  qumail export-identity")
    return 0


def cmd_export_identity(args: argparse.Namespace, config: Config) -> int:
    identity = _unlock(config)
    bundle = identity.public.to_json()

    if args.out:
        # Public data, so not mode 600: the point is to hand it to someone.
        atomic_write_text(Path(args.out), bundle + "\n", private=False)
        print("Public identity written to %s" % args.out)
    else:
        print(bundle)

    print(
        "\nGive the recipient this file, then confirm the fingerprint over a\n"
        "channel an attacker cannot rewrite -- a phone call, in person, anything\n"
        "that is not the same mailbox:\n\n    %s\n"
        % identity.public.pretty_fingerprint(),
        file=sys.stderr,
    )
    return 0


def cmd_import_contact(args: argparse.Namespace, config: Config) -> int:
    path = Path(args.file)
    if not path.exists():
        raise ConfigError("no such file: %s" % path)

    identity = PublicIdentity.from_json(path.read_text(encoding="utf-8"))
    store = ContactStore(config.contacts_path)

    if args.expect_fingerprint:
        expected = args.expect_fingerprint.replace(" ", "").lower()
        if expected != identity.fingerprint:
            raise QuMailError(
                "fingerprint mismatch: the file contains %s but you expected %s. "
                "Do not import this key." % (identity.fingerprint, expected)
            )
        print("Fingerprint matches the one you supplied.")

    changed = store.add(identity, replace=args.replace)
    _print_identity(
        identity, heading="Imported:" if changed else "Already trusted (unchanged):"
    )
    if not args.expect_fingerprint:
        print(
            "\nVerify this fingerprint with the sender out of band before you\n"
            "trust mail from it. Anyone can generate a key claiming any address."
        )
    return 0


def cmd_contacts(args: argparse.Namespace, config: Config) -> int:
    store = ContactStore(config.contacts_path)
    if args.json:
        print(json.dumps(store.to_list(), indent=2, sort_keys=True))
        return 0
    if not len(store):
        print("No trusted contacts yet. Import one with: qumail import-contact <file>")
        return 0
    print("%d trusted contact(s):" % len(store))
    for contact in store:
        print("  %-40s %s" % (contact.address, contact.pretty_fingerprint()))
    return 0


def cmd_remove_contact(args: argparse.Namespace, config: Config) -> int:
    store = ContactStore(config.contacts_path)
    if store.remove(args.fingerprint):
        print("Removed %s" % args.fingerprint)
        return 0
    print("No contact with fingerprint %s" % args.fingerprint, file=sys.stderr)
    return 1


def _read_body(args: argparse.Namespace) -> bytes:
    if args.message is not None:
        return args.message.encode("utf-8")
    if args.file is not None:
        data = Path(args.file).read_bytes()
    elif not sys.stdin.isatty():
        data = sys.stdin.buffer.read()
    else:
        print("Type your message, then press Ctrl+Z (Windows) or Ctrl+D to finish:")
        data = sys.stdin.buffer.read()

    if not data:
        raise ConfigError("refusing to send an empty message")
    if len(data) > MAX_PLAINTEXT_BYTES:
        raise ConfigError(
            "message is %d bytes, over the %d byte limit"
            % (len(data), MAX_PLAINTEXT_BYTES)
        )
    return data


def cmd_send(args: argparse.Namespace, config: Config) -> int:
    store = ContactStore(config.contacts_path)
    recipient = store.resolve(args.to)
    sender = _unlock(config)
    body = _read_body(args)

    envelope = seal(sender, recipient, body, subject=args.subject or "")
    smtp_send(config.smtp, envelope, args.address or recipient.address)

    print("Sent %s to %s (%s)" % (
        envelope.header.message_id, recipient.address, recipient.pretty_fingerprint()
    ))
    return 0


def cmd_receive(args: argparse.Namespace, config: Config) -> int:
    identity = _unlock(config)
    receiver = Receiver(
        config,
        identity,
        ContactStore(config.contacts_path),
        write_html=args.html,
        include_read=args.include_read,
        learn_senders=not args.no_learn,
    )

    if args.once:
        result = receiver.poll_once()
        print(
            "Examined %d QuMail message(s): %d delivered, %d rejected."
            % (result.examined, result.delivered, result.rejected)
        )
        if result.delivered:
            print("Output written to %s" % config.output_dir)
        return 0

    receiver.run_forever()
    return 0


def cmd_web(args: argparse.Namespace, config: Config) -> int:
    from .config import load_web
    from .web.server import WebApp, serve

    web = load_web()
    identity = _unlock(config)

    app = WebApp(
        config,
        identity,
        password_hash=web.password_hash,
        session_secret=web.session_secret,
        secure_cookies=web.secure_cookies,
        include_read=args.include_read,
    )

    host = args.host or web.host
    port = args.port or web.port

    if host not in ("127.0.0.1", "localhost") and not web.secure_cookies:
        print(
            "WARNING: serving on %s without Secure cookies. Put this behind "
            "HTTPS, or sessions can be stolen off the wire." % host,
            file=sys.stderr,
        )

    print("QuMail web inbox: http://%s:%d" % (host, port))
    print("Signed in as %s (%s)" % (identity.address, identity.public.pretty_fingerprint()))
    serve(app, host, port)
    return 0


def cmd_set_web_password(args: argparse.Namespace, config: Config) -> int:
    """Generate the env values the web inbox needs. Prints, never stores."""
    import os
    from getpass import getpass

    from .web.auth import hash_password

    password = os.environ.get("QUMAIL_WEB_PASSWORD") or getpass("New web password: ")
    if not os.environ.get("QUMAIL_WEB_PASSWORD"):
        if password != getpass("Confirm password: "):
            raise ConfigError("passwords did not match")

    print("\nAdd these to your .env (or to Render's environment settings):\n")
    print("QUMAIL_WEB_PASSWORD_HASH=%s" % hash_password(password))
    print("QUMAIL_WEB_SESSION_SECRET=%s" % os.urandom(32).hex())
    print(
        "\nThe session secret keeps you logged in across restarts. Both values "
        "are secrets:\nanyone holding them can sign in as you.",
        file=sys.stderr,
    )
    return 0


def cmd_doctor(args: argparse.Namespace, config: Config) -> int:
    """Check the deployment without sending anything."""
    ok = True

    print("QuMail %s" % __version__)
    print("  home:        %s" % config.home)
    print("  keystore:    %s %s" % (
        config.keystore_path,
        "(present)" if config.keystore_path.exists() else "(MISSING -- run keygen)",
    ))
    ok &= config.keystore_path.exists()

    try:
        identity = _unlock(config)
        _print_identity(identity.public, heading="  identity unlocked:")
    except QuMailError as exc:
        print("  identity:    FAILED -- %s" % exc)
        ok = False

    try:
        store = ContactStore(config.contacts_path)
        print("  contacts:    %d trusted" % len(store))
        if not len(store):
            print("               (you cannot send or receive until you import one)")
    except QuMailError as exc:
        print("  contacts:    FAILED -- %s" % exc)
        ok = False

    for label, loader in (("SMTP", "with_smtp"), ("IMAP", "with_imap")):
        try:
            load_config(**{loader: True})
            print("  %s:        configured" % label)
        except ConfigError as exc:
            print("  %s:        not configured -- %s" % (label, exc))

    print("\n%s" % ("All required checks passed." if ok else "Some checks FAILED."))
    return 0 if ok else 1


# ---------------------------------------------------------------- wiring


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qumail",
        description="Post-quantum hybrid end-to-end encrypted email.",
    )
    parser.add_argument("--version", action="version", version="qumail " + __version__)
    parser.add_argument(
        "--env-file", type=Path, default=None,
        help="path to a .env file (default: ./.env)",
    )
    parser.add_argument(
        "--log-level", default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="override QUMAIL_LOG_LEVEL",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="create a new identity and keystore")
    p.add_argument("--address", required=True, help="your email address")
    p.add_argument(
        "--force", action="store_true",
        help="overwrite an existing keystore (destroys the old private key)",
    )
    p.set_defaults(handler=cmd_keygen, needs=())

    p = sub.add_parser("export-identity", help="print or write your public identity")
    p.add_argument("--out", help="write to this file instead of stdout")
    p.set_defaults(handler=cmd_export_identity, needs=())

    p = sub.add_parser("import-contact", help="trust someone's public identity")
    p.add_argument("file", help="the .json bundle they sent you")
    p.add_argument(
        "--expect-fingerprint",
        help="fingerprint you verified out of band; the import fails if it differs",
    )
    p.add_argument(
        "--replace", action="store_true",
        help="allow replacing a different key already trusted for this fingerprint",
    )
    p.set_defaults(handler=cmd_import_contact, needs=())

    p = sub.add_parser("contacts", help="list trusted contacts")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.set_defaults(handler=cmd_contacts, needs=())

    p = sub.add_parser("remove-contact", help="stop trusting a contact")
    p.add_argument("fingerprint")
    p.set_defaults(handler=cmd_remove_contact, needs=())

    p = sub.add_parser("send", help="encrypt, sign and send a message")
    p.add_argument("--to", required=True, help="recipient address or fingerprint")
    p.add_argument(
        "--address",
        help="deliver to this mailbox instead of the contact's stored address",
    )
    p.add_argument("--subject", help="encrypted subject line")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--message", help="message text")
    group.add_argument("--file", help="read the message body from this file")
    p.set_defaults(handler=cmd_send, needs=("smtp",))

    p = sub.add_parser("receive", help="poll for and decrypt incoming messages")
    p.add_argument("--once", action="store_true", help="one poll, then exit")
    p.add_argument("--html", action="store_true", help="also write an HTML view")
    p.add_argument(
        "--no-learn",
        action="store_true",
        help="do not adopt a sender's key on first contact; require that every "
             "sender was imported and verified beforehand",
    )
    p.add_argument(
        "--include-read",
        action="store_true",
        help="also consider messages already flagged read (needed when sending "
             "to yourself: Gmail marks your own mail read on delivery)",
    )
    p.set_defaults(handler=cmd_receive, needs=("imap",))

    p = sub.add_parser("web", help="run the browser inbox")
    p.add_argument("--host", help="bind address (default 127.0.0.1)")
    p.add_argument("--port", type=int, help="bind port (default 8000, or $PORT)")
    p.add_argument(
        "--include-read",
        action="store_true",
        help="also poll mail already flagged read (needed when mailing yourself)",
    )
    p.set_defaults(handler=cmd_web, needs=("smtp", "imap"))

    p = sub.add_parser(
        "set-web-password", help="generate the web inbox password hash and secret"
    )
    p.set_defaults(handler=cmd_set_web_password, needs=())

    p = sub.add_parser("doctor", help="check configuration and keys")
    p.set_defaults(handler=cmd_doctor, needs=())

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        config = load_config(
            dotenv=args.env_file,
            with_smtp="smtp" in args.needs,
            with_imap="imap" in args.needs,
        )
    except ConfigError as exc:
        configure_logging("INFO", "text")
        print("Configuration error: %s" % exc, file=sys.stderr)
        return 2

    configure_logging(args.log_level or config.log_level, config.log_format)

    try:
        # A hosted deploy starts with an empty volume; restore the identity
        # from the environment before anything tries to unlock it.
        bootstrap_keystore(config)
        return args.handler(args, config)
    except QuMailError as exc:
        # Expected failures: a clear line, no traceback, non-zero exit.
        print("Error: %s" % exc, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())

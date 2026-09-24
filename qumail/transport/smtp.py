"""Sending sealed envelopes over SMTP."""

from __future__ import annotations

import smtplib
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from ..armor import armor
from ..config import SmtpConfig
from ..crypto.envelope import Envelope
from ..errors import TransportError
from ..invites import INVITATION_SUBJECT
from ..logging_setup import get_logger
from .tls import describe, secure_context

log = get_logger(__name__)

SUBJECT_PREFIX = "[QuMail]"

_NOTICE = (
    "This message was sent with QuMail.\n"
    "\n"
    "The content is end-to-end encrypted with a hybrid X25519 + ML-KEM-768 key\n"
    "exchange and AES-256-GCM, and signed by the sender. Only the intended\n"
    "recipient's QuMail keystore can read it.\n"
)


def _validate_address(address: str) -> str:
    """Reject anything that could inject an extra header.

    Python's email package is careful, but a bare CR/LF in an address is the
    classic header-injection vector and there is no reason to accept one.
    """
    cleaned = address.strip()
    if not cleaned or any(ch in cleaned for ch in "\r\n\t") or "@" not in cleaned:
        raise TransportError("invalid email address: %r" % address)
    if len(cleaned) > 320:
        raise TransportError("email address is too long")
    return cleaned


def build_message(envelope: Envelope, *, from_address: str, to_address: str) -> EmailMessage:
    """Render an envelope as an RFC 5322 message.

    The subject carries only the message id, which is already public metadata
    inside the envelope header. The user's own subject line is encrypted.
    """
    message = EmailMessage()
    message["From"] = _validate_address(from_address)
    message["To"] = _validate_address(to_address)
    message["Subject"] = "%s %s" % (SUBJECT_PREFIX, envelope.header.message_id)
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid(domain="qumail.local")
    message["X-QuMail-Version"] = str(envelope.header.version)
    message.set_content(_NOTICE + "\n" + armor(envelope.to_json()) + "\n")
    return message


def _deliver(config: SmtpConfig, message: EmailMessage) -> None:
    """Open a verified TLS session and hand over one message."""
    context = secure_context()
    try:
        if config.security == "ssl":
            client = smtplib.SMTP_SSL(
                config.host, config.port, timeout=config.timeout, context=context
            )
        else:
            client = smtplib.SMTP(config.host, config.port, timeout=config.timeout)

        with client:
            client.ehlo()
            if config.security == "starttls":
                if not client.has_extn("starttls"):
                    # Never fall back to plaintext: that is exactly what a
                    # stripping attacker wants.
                    raise TransportError(
                        "%s does not offer STARTTLS; refusing to send in the clear"
                        % config.host
                    )
                client.starttls(context=context)
                client.ehlo()

            sock = getattr(client, "sock", None)
            if sock is not None:
                log.debug("SMTP TLS established: %s", describe(sock))

            client.login(config.username, config.password)
            client.send_message(message)

    except smtplib.SMTPAuthenticationError as exc:
        raise TransportError(
            "SMTP authentication failed for %s -- check the account credentials "
            "and that an app password is being used where required" % config.username
        ) from exc
    except smtplib.SMTPException as exc:
        raise TransportError("SMTP error: %s" % exc.__class__.__name__) from exc
    except OSError as exc:
        raise TransportError(
            "could not reach SMTP server %s:%d" % (config.host, config.port)
        ) from exc


def send_invitation(config: SmtpConfig, body: str, to_address: str, *,
                    from_address: str) -> None:
    """Send a plaintext contact request carrying a public key.

    Deliberately not encrypted: the whole point is that there is not yet a key
    to encrypt to, and a public key is not a secret.
    """
    message = EmailMessage()
    message["From"] = _validate_address(from_address)
    message["To"] = _validate_address(to_address)
    message["Subject"] = INVITATION_SUBJECT
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid(domain="qumail.local")
    message.set_content(body)

    _deliver(config, message)
    log.info("sent contact request to %s", to_address)


def send(config: SmtpConfig, envelope: Envelope, to_address: str) -> None:
    """Deliver `envelope`. Raises `TransportError` on any failure."""
    message = build_message(
        envelope, from_address=config.from_address, to_address=to_address
    )
    _deliver(config, message)
    log.info(
        "sent message %s to %s", envelope.header.message_id, to_address
    )

"""HTTP server for the web inbox.

Routing is an explicit table. There is no static file directory and no path is
ever built from a URL, so the whole class of path-traversal bugs is absent by
construction rather than by filtering.

A background thread polls IMAP and decrypts into the same output directory the
CLI uses, so the web inbox and `qumail receive` are two views of one state.
"""

from __future__ import annotations

import json
import threading
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional
from urllib.parse import parse_qs, urlparse

from ..config import Config
from ..contacts import ContactStore
from ..crypto.envelope import seal
from ..crypto.keys import PrivateIdentity, PublicIdentity
from ..errors import EnvelopeError, QuMailError
from ..invites import InviteStore, build_invitation_body
from ..logging_setup import get_logger
from ..receiver import Receiver
from ..transport.smtp import send as smtp_send, send_invitation
from .auth import SESSION_COOKIE, SessionManager, verify_password
from .pages import SCRIPT, STYLESHEET, inbox_page, login_page
from .store import MessageStore

log = get_logger(__name__)

# A form post of a message body; the envelope limit is enforced later.
MAX_REQUEST_BYTES = 1024 * 1024

SECURITY_HEADERS = {
    # No inline script or style, nothing loaded from anywhere else, no framing.
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'self'; script-src 'self'; "
        "connect-src 'self'; form-action 'self'; base-uri 'none'; "
        "frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    # The inbox is decrypted mail; never let a proxy or browser cache it.
    "Cache-Control": "no-store, max-age=0",
}


class WebApp:
    """Shared state behind the request handlers."""

    def __init__(
        self,
        config: Config,
        identity: PrivateIdentity,
        *,
        password_hash: str,
        session_secret: Optional[bytes] = None,
        secure_cookies: bool = True,
        poll_interval: Optional[int] = None,
        include_read: bool = False,
    ) -> None:
        self.config = config
        self.identity = identity
        self.password_hash = password_hash
        self.sessions = SessionManager(session_secret, secure_cookies=secure_cookies)
        self.contacts = ContactStore(config.contacts_path)
        self.store = MessageStore(config.output_dir, config.state_dir / "sent")
        self.invites = InviteStore(config.state_dir / "pending")
        self.receiver = Receiver(
            config, identity, self.contacts, include_read=include_read
        )
        self.poll_interval = poll_interval or config.policy.poll_interval
        self.last_poll = "not yet polled"
        self._stop = threading.Event()
        self._send_lock = threading.Lock()

    # ---------- background polling ----------

    def start_poller(self) -> None:
        thread = threading.Thread(target=self._poll_loop, name="qumail-poll", daemon=True)
        thread.start()

    def _poll_loop(self) -> None:
        backoff = self.poll_interval
        while not self._stop.is_set():
            try:
                result = self.receiver.poll_once()
                backoff = self.poll_interval
                self.last_poll = "last checked %s" % time.strftime("%H:%M:%S")
                if result.delivered:
                    log.info("web poller delivered %d message(s)", result.delivered)
            except QuMailError as exc:
                self.last_poll = "mail check failed: %s" % exc
                log.warning("poll failed: %s", exc)
                backoff = min(backoff * 2, 300)
            except Exception:  # keep the daemon alive whatever happens
                self.last_poll = "mail check failed"
                log.exception("unexpected error in poll loop")
                backoff = min(backoff * 2, 300)
            self._stop.wait(backoff)

    def stop(self) -> None:
        self._stop.set()

    # ---------- actions ----------

    def send_message(self, to: str, subject: str, body: str) -> str:
        """Seal and send. Returns a message for the UI."""
        to = to.strip()
        if not to:
            raise QuMailError("a recipient address is required")
        if not body.strip():
            raise QuMailError("refusing to send an empty message")

        recipient = self.contacts.resolve(to)

        # One send at a time: SMTP sessions and the sent log are not reentrant.
        with self._send_lock:
            envelope = seal(self.identity, recipient, body.encode("utf-8"), subject=subject)
            smtp_send(self.config.smtp, envelope, recipient.address)
            self.store.record_sent(
                message_id=envelope.header.message_id,
                recipient_fingerprint=recipient.fingerprint,
                recipient_address=recipient.address,
                subject=subject,
                body=body.encode("utf-8"),
                timestamp=envelope.header.timestamp,
            )
        return "Sent to %s" % recipient.address

    def invite(self, to: str) -> str:
        """Email this identity's public key so a stranger can reply encrypted."""
        to = to.strip()
        if not to:
            raise QuMailError("an email address is required")

        with self._send_lock:
            send_invitation(
                self.config.smtp,
                build_invitation_body(self.identity.public),
                to,
                from_address=self.config.smtp.from_address,
            )
        return (
            "Contact request sent to %s. Once they accept and reply, their key "
            "arrives automatically." % to
        )

    def add_contact(self, bundle_text: str) -> str:
        """Import a pasted public identity."""
        if not bundle_text.strip():
            raise QuMailError("paste the contents of their identity file")
        try:
            identity = PublicIdentity.from_json(bundle_text)
        except EnvelopeError as exc:
            raise QuMailError("that is not a valid QuMail identity: %s" % exc) from exc

        added = self.contacts.add(identity)
        self.invites.remove(identity.fingerprint)
        return "%s %s (%s)" % (
            "Added" if added else "Already trusted:",
            identity.address,
            identity.pretty_fingerprint(),
        )

    def accept_invite(self, fingerprint: str) -> str:
        pending = self.invites.get(fingerprint.strip())
        if pending is None:
            raise QuMailError("no pending contact request with that fingerprint")

        self.contacts.add(pending.identity)
        self.invites.remove(pending.fingerprint)
        return "Accepted %s (%s)" % (
            pending.identity.address, pending.identity.pretty_fingerprint()
        )

    def dismiss_invite(self, fingerprint: str) -> str:
        if not self.invites.remove(fingerprint.strip()):
            raise QuMailError("no pending contact request with that fingerprint")
        return "Contact request dismissed."


def _make_handler(app: WebApp) -> type:
    class Handler(BaseHTTPRequestHandler):
        server_version = "QuMail"
        sys_version = ""  # do not advertise the Python version
        protocol_version = "HTTP/1.1"

        # ---------- plumbing ----------

        def log_message(self, fmt: str, *args: object) -> None:
            log.debug("%s %s", self.address_string(), fmt % args)

        def _client(self) -> str:
            forwarded = self.headers.get("X-Forwarded-For", "")
            if forwarded:
                return forwarded.split(",")[0].strip()[:64]
            return self.client_address[0]

        def _respond(
            self,
            status: HTTPStatus,
            body: bytes,
            content_type: str = "text/html; charset=utf-8",
            extra: Optional[Dict[str, str]] = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for name, value in SECURITY_HEADERS.items():
                self.send_header(name, value)
            for name, value in (extra or {}).items():
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _redirect(self, location: str, extra: Optional[Dict[str, str]] = None) -> None:
            headers = {"Location": location}
            headers.update(extra or {})
            self._respond(HTTPStatus.SEE_OTHER, b"", "text/plain", headers)

        def _session_token(self) -> Optional[str]:
            raw = self.headers.get("Cookie")
            if not raw:
                return None
            try:
                cookie = SimpleCookie()
                cookie.load(raw)
            except Exception:
                return None
            morsel = cookie.get(SESSION_COOKIE)
            return morsel.value if morsel else None

        def _authenticated(self) -> Optional[str]:
            token = self._session_token()
            return token if app.sessions.validate(token) else None

        def _read_form(self) -> Dict[str, str]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return {}
            if length <= 0 or length > MAX_REQUEST_BYTES:
                return {}
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}

        # ---------- routes ----------

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            path = urlparse(self.path).path

            if path == "/healthz":
                # Unauthenticated on purpose: Render polls it. Reveals nothing.
                self._respond(HTTPStatus.OK, b'{"status":"ok"}', "application/json")
                return
            if path == "/style.css":
                self._respond(
                    HTTPStatus.OK, STYLESHEET.encode("utf-8"), "text/css; charset=utf-8"
                )
                return
            if path == "/app.js":
                self._respond(
                    HTTPStatus.OK,
                    SCRIPT.encode("utf-8"),
                    "application/javascript; charset=utf-8",
                )
                return
            if path == "/login":
                self._respond(HTTPStatus.OK, login_page().encode("utf-8"))
                return

            token = self._authenticated()
            if not token:
                self._redirect("/login")
                return

            if path == "/status.json":
                payload = json.dumps({"count": app.store.count()}).encode("utf-8")
                self._respond(HTTPStatus.OK, payload, "application/json")
                return
            if path == "/":
                self._render_inbox(token)
                return

            self._respond(HTTPStatus.NOT_FOUND, b"Not found", "text/plain")

        def do_HEAD(self) -> None:  # noqa: N802
            self.do_GET()

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path

            if path == "/login":
                self._handle_login()
                return

            token = self._authenticated()
            if not token:
                self._redirect("/login")
                return

            form = self._read_form()
            if not app.sessions.check_csrf(token, form.get("csrf")):
                self._respond(HTTPStatus.FORBIDDEN, b"Bad CSRF token", "text/plain")
                return

            if path == "/logout":
                self._redirect(
                    "/login", {"Set-Cookie": app.sessions.clear_cookie_header()}
                )
                return
            if path == "/send":
                self._handle_send(form)
                return
            if path == "/contacts/invite":
                self._act(lambda: app.invite(form.get("to", "")))
                return
            if path == "/contacts/add":
                self._act(lambda: app.add_contact(form.get("bundle", "")))
                return
            if path == "/contacts/accept":
                self._act(lambda: app.accept_invite(form.get("fingerprint", "")))
                return
            if path == "/contacts/dismiss":
                self._act(lambda: app.dismiss_invite(form.get("fingerprint", "")))
                return

            self._respond(HTTPStatus.NOT_FOUND, b"Not found", "text/plain")

        # ---------- handlers ----------

        def _handle_login(self) -> None:
            client = self._client()
            locked = app.sessions.throttle.locked_for(client)
            if locked:
                page = login_page(
                    error="Too many attempts. Try again in %d seconds." % locked
                )
                self._respond(HTTPStatus.TOO_MANY_REQUESTS, page.encode("utf-8"))
                return

            form = self._read_form()
            if verify_password(form.get("password", ""), app.password_hash):
                app.sessions.throttle.record_success(client)
                token = app.sessions.issue()
                log.info("web login succeeded from %s", client)
                self._redirect("/", {"Set-Cookie": app.sessions.cookie_header(token)})
                return

            app.sessions.throttle.record_failure(client)
            log.warning("web login failed from %s", client)
            self._respond(
                HTTPStatus.UNAUTHORIZED,
                login_page(error="Incorrect password.").encode("utf-8"),
            )

        def _act(self, action) -> None:
            """Run an action and report the outcome on the inbox page."""
            try:
                self._redirect("/?sent=%s" % _quote(action()))
            except QuMailError as exc:
                self._redirect("/?error=%s" % _quote(str(exc)))

        def _handle_send(self, form: Dict[str, str]) -> None:
            self._act(
                lambda: app.send_message(
                    form.get("to", ""), form.get("subject", ""), form.get("body", "")
                )
            )

        def _render_inbox(self, token: str) -> None:
            query = parse_qs(urlparse(self.path).query)
            peer = (query.get("peer") or [None])[0]
            threads = app.store.threads()
            selected = next(
                (t for t in threads if t.peer_fingerprint == peer),
                threads[0] if threads else None,
            )
            page = inbox_page(
                identity=app.identity.public,
                threads=threads,
                selected=selected,
                csrf=app.sessions.csrf_token(token),
                count=app.store.count(),
                contacts=list(app.contacts),
                invites=app.invites.all(),
                message=(query.get("sent") or [""])[0][:200],
                error=(query.get("error") or [""])[0][:200],
                last_poll=app.last_poll,
            )
            self._respond(HTTPStatus.OK, page.encode("utf-8"))

    return Handler


def _quote(text: str) -> str:
    from urllib.parse import quote

    return quote(text[:200], safe="")


def serve(app: WebApp, host: str, port: int) -> None:
    """Run the web inbox until interrupted."""
    app.start_poller()
    httpd = ThreadingHTTPServer((host, port), _make_handler(app))
    httpd.daemon_threads = True

    shown = "localhost" if host in ("127.0.0.1", "0.0.0.0") else host
    log.info("QuMail web inbox on http://%s:%d", shown, port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        app.stop()
        httpd.server_close()

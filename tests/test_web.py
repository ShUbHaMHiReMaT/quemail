"""The web inbox: authentication, routing, and output escaping."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from qumail.contacts import ContactStore
from qumail.errors import ConfigError
from qumail.web.auth import (
    MAX_ATTEMPTS,
    LoginThrottle,
    SessionManager,
    hash_password,
    verify_password,
)
from qumail.web.pages import esc, inbox_page, login_page
from qumail.web.server import SECURITY_HEADERS, WebApp, _make_handler
from qumail.web.store import MessageStore

PASSWORD = "a-long-enough-web-password"


class TestPasswordHashing:
    def test_round_trip(self):
        encoded = hash_password(PASSWORD)
        assert verify_password(PASSWORD, encoded)
        assert not verify_password(PASSWORD + "!", encoded)

    def test_password_is_not_recoverable_from_the_hash(self):
        assert PASSWORD not in hash_password(PASSWORD)

    def test_each_hash_uses_a_fresh_salt(self):
        assert hash_password(PASSWORD) != hash_password(PASSWORD)

    def test_short_password_refused(self):
        with pytest.raises(ConfigError, match="at least"):
            hash_password("short")

    @pytest.mark.parametrize(
        "bad", ["", "notahash", "scrypt$bad", "md5$1$1$1$aa$bb", "scrypt$1$1$1$aa$bb"]
    )
    def test_malformed_hashes_never_authenticate(self, bad):
        assert not verify_password(PASSWORD, bad)

    def test_absurd_cost_in_a_hash_is_refused(self):
        """A hostile hash string must not be able to demand huge memory."""
        assert not verify_password(PASSWORD, "scrypt$1073741824$8$1$aa$bb")


class TestSessions:
    def test_issued_token_validates(self):
        manager = SessionManager(b"k" * 32)
        assert manager.validate(manager.issue())

    def test_tampered_token_is_rejected(self):
        manager = SessionManager(b"k" * 32)
        token = manager.issue()
        payload, signature = token.split(".")
        assert not manager.validate(payload + "." + signature[:-2] + "xy")
        assert not manager.validate("x" + payload + "." + signature)

    def test_token_from_another_secret_is_rejected(self):
        issued = SessionManager(b"k" * 32).issue()
        assert not SessionManager(b"j" * 32).validate(issued)

    @pytest.mark.parametrize("bad", [None, "", "no-dot", "a.b.c", "!!!.???"])
    def test_malformed_tokens_are_rejected(self, bad):
        assert not SessionManager(b"k" * 32).validate(bad)

    def test_expired_token_is_rejected(self, monkeypatch):
        manager = SessionManager(b"k" * 32)
        token = manager.issue()

        later = time.time() + 24 * 3600  # captured before patching, or it recurses
        monkeypatch.setattr(time, "time", lambda: later)
        assert not manager.validate(token)

    def test_csrf_is_bound_to_the_session(self):
        manager = SessionManager(b"k" * 32)
        first, second = manager.issue(), manager.issue()

        assert manager.check_csrf(first, manager.csrf_token(first))
        assert not manager.check_csrf(first, manager.csrf_token(second))
        assert not manager.check_csrf(first, None)
        assert not manager.check_csrf(first, "")

    def test_cookie_is_hardened(self):
        header = SessionManager(b"k" * 32, secure_cookies=True).cookie_header("t")
        assert "HttpOnly" in header
        assert "SameSite=Strict" in header
        assert "Secure" in header


class TestThrottle:
    def test_locks_out_after_repeated_failures(self):
        throttle = LoginThrottle()
        assert throttle.locked_for("1.2.3.4") == 0

        for _ in range(MAX_ATTEMPTS):
            throttle.record_failure("1.2.3.4")
        assert throttle.locked_for("1.2.3.4") > 0

    def test_success_clears_the_counter(self):
        throttle = LoginThrottle()
        for _ in range(MAX_ATTEMPTS):
            throttle.record_failure("1.2.3.4")
        throttle.record_success("1.2.3.4")
        assert throttle.locked_for("1.2.3.4") == 0

    def test_lockout_is_per_client(self):
        throttle = LoginThrottle()
        for _ in range(MAX_ATTEMPTS):
            throttle.record_failure("1.2.3.4")
        assert throttle.locked_for("5.6.7.8") == 0


class TestEscaping:
    def test_esc_neutralises_markup(self):
        assert esc("<script>") == "&lt;script&gt;"
        assert esc('" onload="x') == "&quot; onload=&quot;x"

    def test_login_error_is_escaped(self):
        page = login_page(error="<img src=x onerror=alert(1)>")
        assert "<img" not in page
        assert "&lt;img" in page

    def test_message_bodies_are_escaped(self, alice, bob, config, tmp_path):
        from qumail.web.store import Message, Thread

        hostile = Thread(
            peer_fingerprint="a" * 32,
            peer_address="<b>evil</b>@example.com",
            messages=[
                Message(
                    message_id="b" * 32,
                    peer_fingerprint="a" * 32,
                    peer_address="<b>evil</b>@example.com",
                    subject="<script>alert(1)</script>",
                    body="<img src=x onerror=alert(2)>",
                    timestamp=int(time.time()),
                    outgoing=False,
                )
            ],
        )
        page = inbox_page(
            identity=alice.public,
            threads=[hostile],
            selected=hostile,
            csrf="token",
            count=1,
        )
        assert "<script>alert(1)</script>" not in page
        assert "<img src=x" not in page
        assert "&lt;script&gt;" in page


class TestStore:
    def test_sent_and_received_merge_into_one_thread(self, config, alice, bob):
        from qumail.crypto.envelope import EnvelopeHeader, new_message_id
        from qumail.delivery import deliver

        store = MessageStore(config.output_dir, config.state_dir / "sent")

        header = EnvelopeHeader(
            version=1,
            message_id=new_message_id(),
            timestamp=int(time.time()) - 60,
            sender_fingerprint=alice.fingerprint,
            recipient_fingerprint=bob.fingerprint,
            subject="in",
        )
        deliver(config.output_dir, header, alice.address, b"incoming")
        store.record_sent(
            message_id=new_message_id(),
            recipient_fingerprint=alice.fingerprint,
            recipient_address=alice.address,
            subject="out",
            body=b"outgoing",
            timestamp=int(time.time()),
        )

        threads = store.threads()
        assert len(threads) == 1
        assert [m.outgoing for m in threads[0].messages] == [False, True]
        assert store.count() == 2

    def test_unreadable_files_are_skipped(self, config):
        config.output_dir.mkdir(parents=True, exist_ok=True)
        (config.output_dir / "broken.json").write_text("{not json")
        assert MessageStore(config.output_dir, config.state_dir / "sent").threads() == []


@pytest.fixture
def server(config, bob, alice):
    """A live server on a random port, with Alice trusted."""
    ContactStore(config.contacts_path).add(alice.public)
    app = WebApp(
        config,
        bob,
        password_hash=hash_password(PASSWORD),
        session_secret=b"k" * 32,
        secure_cookies=False,
    )
    # No poller: these tests must not touch the network.
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(app))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield "http://127.0.0.1:%d" % httpd.server_address[1], app
    httpd.shutdown()
    httpd.server_close()


def _request(url, *, data=None, cookie=None, redirect=False):
    request = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    if cookie:
        request.add_header("Cookie", cookie)

    opener = urllib.request.build_opener()
    if not redirect:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args):
                return None

        opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=10) as response:
            return response.status, response.read().decode(), dict(response.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(), dict(exc.headers)


class TestRoutes:
    def test_healthz_needs_no_session(self, server):
        base, _ = server
        status, body, _ = _request(base + "/healthz")
        assert status == 200
        assert json.loads(body)["status"] == "ok"

    def test_inbox_requires_a_session(self, server):
        base, _ = server
        status, _, headers = _request(base + "/")
        assert status == 303
        assert headers["Location"] == "/login"

    def test_status_json_requires_a_session(self, server):
        base, _ = server
        status, _, _ = _request(base + "/status.json")
        assert status == 303

    def test_security_headers_are_present(self, server):
        base, _ = server
        _, _, headers = _request(base + "/login")
        for name, value in SECURITY_HEADERS.items():
            assert headers[name] == value
        assert "unsafe-inline" not in headers["Content-Security-Policy"]

    def test_server_does_not_advertise_its_python_version(self, server):
        base, _ = server
        _, _, headers = _request(base + "/login")
        assert "Python" not in headers.get("Server", "")

    def test_wrong_password_is_rejected(self, server):
        base, _ = server
        status, body, headers = _request(
            base + "/login", data=b"password=wrong-password-here"
        )
        assert status == 401
        assert "Incorrect password" in body
        assert "Set-Cookie" not in headers

    def test_login_then_read_the_inbox(self, server):
        base, _ = server
        status, _, headers = _request(
            base + "/login", data=("password=" + PASSWORD).encode()
        )
        assert status == 303
        cookie = headers["Set-Cookie"]
        assert "HttpOnly" in cookie

        session = cookie.split(";")[0]
        status, body, _ = _request(base + "/", cookie=session)
        assert status == 200
        assert "QuMail" in body

    def test_send_without_a_csrf_token_is_refused(self, server):
        base, _ = server
        _, _, headers = _request(base + "/login", data=("password=" + PASSWORD).encode())
        session = headers["Set-Cookie"].split(";")[0]

        status, body, _ = _request(
            base + "/send", data=b"to=x@example.com&body=hi", cookie=session
        )
        assert status == 403
        assert "CSRF" in body

    def test_unknown_paths_404(self, server):
        base, _ = server
        _, _, headers = _request(base + "/login", data=("password=" + PASSWORD).encode())
        session = headers["Set-Cookie"].split(";")[0]
        status, _, _ = _request(base + "/../etc/passwd", cookie=session)
        assert status in (400, 404)

    def test_logout_clears_the_cookie(self, server):
        base, app = server
        _, _, headers = _request(base + "/login", data=("password=" + PASSWORD).encode())
        session_cookie = headers["Set-Cookie"].split(";")[0]
        token = session_cookie.split("=", 1)[1]

        csrf = app.sessions.csrf_token(token)
        status, _, headers = _request(
            base + "/logout",
            data=("csrf=" + csrf).encode(),
            cookie=session_cookie,
        )
        assert status == 303
        assert "Max-Age=0" in headers["Set-Cookie"]

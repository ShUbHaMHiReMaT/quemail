"""HTML for the web inbox.

Plain string templates rather than a template engine -- one fewer dependency
in a process that holds a private key. Every interpolated value goes through
`esc()`; there is no path that writes caller data into the page unescaped.

The stylesheet and script are served as separate routes so the Content-Security
-Policy can forbid inline script entirely.
"""

from __future__ import annotations

from html import escape as _escape
from typing import List, Optional

from ..crypto.keys import PublicIdentity
from .store import Thread


def esc(value: object) -> str:
    return _escape(str(value), quote=True)


STYLESHEET = """
:root{
  --bg:#f4f5f7; --panel:#fff; --ink:#1a1d21; --muted:#6b7280; --line:#e3e6ea;
  --accent:#2f5fd0; --accent-ink:#fff; --ok:#12805c; --warn:#a4552b;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#15171a; --panel:#1d2024; --ink:#e8eaed; --muted:#9aa2ad; --line:#2c3138;
    --accent:#5b8def; --accent-ink:#0d1117; --ok:#3fbf92; --warn:#e0975f;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:14px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
a{color:var(--accent)}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:1rem;
  padding:.7rem 1rem;background:var(--panel);border-bottom:1px solid var(--line);
  position:sticky;top:0;z-index:5;flex-wrap:wrap}
.brand{font-weight:650;letter-spacing:-.01em}
.brand span{color:var(--muted);font-weight:400;margin-left:.5rem;font-size:.85em}
.fp{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem;
  color:var(--muted)}
.layout{display:grid;grid-template-columns:270px 1fr;gap:1px;background:var(--line);
  min-height:calc(100vh - 53px)}
@media (max-width:760px){.layout{grid-template-columns:1fr}}
.side,.main{background:var(--bg);padding:1rem}
.side{border-right:1px solid var(--line)}
.side h2,.main h2{font-size:.75rem;text-transform:uppercase;letter-spacing:.08em;
  color:var(--muted);margin:.2rem 0 .8rem}
.thread{display:block;padding:.6rem .7rem;border-radius:8px;text-decoration:none;
  color:inherit;margin-bottom:.3rem;border:1px solid transparent}
.thread:hover{background:var(--panel)}
.thread.active{background:var(--panel);border-color:var(--line)}
.thread .who{font-weight:600;word-break:break-all}
.thread .peek{color:var(--muted);font-size:.85em;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.msgs{display:flex;flex-direction:column;gap:.6rem;margin-bottom:1.2rem}
.msg{max-width:min(42rem,85%);padding:.6rem .8rem;border-radius:12px;
  background:var(--panel);border:1px solid var(--line)}
.msg.out{align-self:flex-end;background:var(--accent);color:var(--accent-ink);
  border-color:transparent}
.msg .meta{font-size:.75rem;opacity:.75;margin-bottom:.25rem}
.msg .subject{font-weight:600}
.msg pre{margin:.3rem 0 0;white-space:pre-wrap;word-break:break-word;
  font:inherit}
form.compose{background:var(--panel);border:1px solid var(--line);
  border-radius:10px;padding:.8rem;display:grid;gap:.5rem}
input,textarea,button,select{font:inherit;color:inherit}
input,textarea,select{width:100%;padding:.5rem .6rem;border:1px solid var(--line);
  border-radius:7px;background:var(--bg)}
textarea{min-height:5.5rem;resize:vertical}
button{background:var(--accent);color:var(--accent-ink);border:0;border-radius:7px;
  padding:.55rem 1.1rem;font-weight:600;cursor:pointer;justify-self:start}
button:hover{filter:brightness(1.08)}
.note{color:var(--muted);font-size:.85rem}
.banner{padding:.6rem .8rem;border-radius:8px;margin-bottom:.9rem;
  border:1px solid var(--line);background:var(--panel)}
.banner.ok{border-left:3px solid var(--ok)}
.banner.err{border-left:3px solid var(--warn)}
.empty{color:var(--muted);padding:2rem 0;text-align:center}
.login{max-width:22rem;margin:12vh auto;background:var(--panel);
  border:1px solid var(--line);border-radius:12px;padding:1.5rem}
.login h1{margin:0 0 .3rem;font-size:1.15rem}
.login form{display:grid;gap:.7rem;margin-top:1rem}
.badge{display:inline-block;font-size:.7rem;padding:.1rem .45rem;border-radius:99px;
  background:var(--bg);border:1px solid var(--line);color:var(--muted)}
"""

SCRIPT = """
// Poll for new mail and refresh the thread when the count changes.
(function () {
  var marker = document.body.getAttribute('data-count');
  if (marker === null) return;
  setInterval(function () {
    fetch('status.json', { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (d && String(d.count) !== marker) location.reload();
      })
      .catch(function () { /* offline; try again next tick */ });
  }, 5000);
})();
"""


def _document(title: str, body: str, *, count: Optional[int] = None) -> str:
    attr = ' data-count="%s"' % esc(count) if count is not None else ""
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1,'
        'viewport-fit=cover">'
        "<title>%s</title>"
        '<link rel="stylesheet" href="/style.css">'
        "</head><body%s>%s"
        '<script src="/app.js"></script>'
        "</body></html>"
    ) % (esc(title), attr, body)


def login_page(*, error: str = "") -> str:
    banner = '<div class="banner err">%s</div>' % esc(error) if error else ""
    body = (
        '<div class="login">'
        "<h1>QuMail</h1>"
        '<p class="note">Post-quantum encrypted mail.</p>'
        "%s"
        '<form method="post" action="/login">'
        '<input type="password" name="password" placeholder="Password" '
        'autocomplete="current-password" autofocus required>'
        "<button type=\"submit\">Unlock</button>"
        "</form></div>"
    ) % banner
    return _document("QuMail", body)


def _thread_list(threads: List[Thread], selected: Optional[str]) -> str:
    if not threads:
        return '<p class="note">No conversations yet.</p>'

    rows = []
    for thread in threads:
        latest = thread.latest
        peek = (latest.body.strip().splitlines() or [""])[0] if latest else ""
        rows.append(
            '<a class="thread%s" href="/?peer=%s">'
            '<div class="who">%s</div>'
            '<div class="peek">%s</div>'
            '<div class="fp">%s</div>'
            "</a>"
            % (
                " active" if thread.peer_fingerprint == selected else "",
                esc(thread.peer_fingerprint),
                esc(thread.peer_address),
                esc(peek[:60]),
                esc(thread.pretty_fingerprint),
            )
        )
    return "".join(rows)


def _messages(thread: Optional[Thread]) -> str:
    if thread is None:
        return (
            '<div class="empty">Pick a conversation, or send to a new address '
            "below.</div>"
        )
    if not thread.messages:
        return '<div class="empty">No messages yet.</div>'

    items = []
    for message in thread.messages:
        subject = (
            '<div class="subject">%s</div>' % esc(message.subject)
            if message.subject
            else ""
        )
        items.append(
            '<div class="msg%s"><div class="meta">%s &middot; %s</div>%s'
            "<pre>%s</pre></div>"
            % (
                " out" if message.outgoing else "",
                "you" if message.outgoing else esc(thread.peer_address),
                esc(message.when),
                subject,
                esc(message.body),
            )
        )
    return '<div class="msgs">%s</div>' % "".join(items)


def inbox_page(
    *,
    identity: PublicIdentity,
    threads: List[Thread],
    selected: Optional[Thread],
    csrf: str,
    count: int,
    message: str = "",
    error: str = "",
    last_poll: str = "",
) -> str:
    banner = ""
    if message:
        banner += '<div class="banner ok">%s</div>' % esc(message)
    if error:
        banner += '<div class="banner err">%s</div>' % esc(error)

    to_value = esc(selected.peer_address) if selected else ""

    body = (
        '<div class="topbar">'
        '<div class="brand">QuMail<span>%s</span></div>'
        '<div class="fp">your fingerprint: %s</div>'
        '<form method="post" action="/logout" style="margin:0">'
        '<input type="hidden" name="csrf" value="%s">'
        "<button type=\"submit\">Sign out</button></form>"
        "</div>"
        '<div class="layout">'
        '<div class="side"><h2>Conversations</h2>%s'
        '<p class="note" style="margin-top:1rem">%s</p></div>'
        '<div class="main">%s%s'
        '<form class="compose" method="post" action="/send">'
        '<input type="hidden" name="csrf" value="%s">'
        '<input name="to" placeholder="Recipient email address" value="%s" required>'
        '<input name="subject" placeholder="Subject (encrypted)">'
        '<textarea name="body" placeholder="Message" required></textarea>'
        "<button type=\"submit\">Send encrypted</button>"
        "</form></div></div>"
    ) % (
        esc(identity.address),
        esc(identity.pretty_fingerprint()),
        esc(csrf),
        _thread_list(threads, selected.peer_fingerprint if selected else None),
        esc(last_poll),
        banner,
        _messages(selected),
        esc(csrf),
        to_value,
    )
    return _document("QuMail", body, count=count)

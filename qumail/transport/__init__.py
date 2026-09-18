"""Mail transport with verified TLS.

Both submodules build their SSL context through `tls.secure_context()`. The
stdlib defaults are not safe here: on Python 3.9, `smtplib.SMTP.starttls()`
and `imaplib.IMAP4_SSL()` called without a context fall back to
`ssl._create_stdlib_context()`, which sets `check_hostname=False` and
`verify_mode=CERT_NONE` -- no certificate validation at all.
"""

# debug_imap_prompt.py
import imaplib, getpass

IMAP_HOST = "imap.gmail.com"
IMAP_PORT = 993

email = input("Email: ").strip()
pw = getpass.getpass("App password (16 chars, no spaces): ").strip()

try:
    M = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
    print("[debug_imap_prompt] Attempting login for:", email)
    M.login(email, pw)
    print("[debug_imap_prompt] LOGIN OK")
    M.logout()
except imaplib.IMAP4.error as e:
    print("[debug_imap_prompt] IMAP4.error:", repr(e))
except Exception as e:
    print("[debug_imap_prompt] Other exception:", repr(e))

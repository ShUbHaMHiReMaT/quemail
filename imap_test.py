# imap_test.py
import imaplib
EMAIL = "shubhamhiremath12@gmail.com"
APP_PW = "hagusyzrlycazzcy"

try:
    M = imaplib.IMAP4_SSL("imap.gmail.com", 993)
    M.login(EMAIL, APP_PW)
    print("IMAP login OK")
    M.logout()
except Exception as e:
    print("IMAP login failed:", e)

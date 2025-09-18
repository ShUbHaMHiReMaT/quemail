# Server.py
import os
import sys
import time
import imaplib
import email
import base64
import json
from hashlib import sha256
from Crypto.Cipher import AES  # pip install pycryptodome

from kyber import Kyber768

# ---------- Helpers ----------
def derive_aes_key_from_shared_secret(shared_secret_bytes, info=b"qumail-aes-key", length=32):
    return sha256(shared_secret_bytes + info).digest()[:length]

def aes_gcm_decrypt(key, nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# ---------- Config ----------
IMAP_HOST = os.environ.get("QUMAIL_IMAP_HOST", "imap.gmail.com")
IMAP_PORT = int(os.environ.get("QUMAIL_IMAP_PORT", 993))
RECIPIENT_EMAIL = os.environ.get("QUMAIL_RECIPIENT_EMAIL", "udaymathapati07@gmail.com")
RECIPIENT_APP_PW = os.environ.get("QUMAIL_RECIPIENT_APP_PASSWORD", "bxbibwynqgpiljjw")
CHECK_INTERVAL = int(os.environ.get("QUMAIL_CHECK_INTERVAL", 6))

if not (RECIPIENT_EMAIL and RECIPIENT_APP_PW):
    print("Please set QUMAIL_RECIPIENT_EMAIL and QUMAIL_RECIPIENT_APP_PASSWORD")
    sys.exit(1)

sk_path = "recipient_sk.bin"
if not os.path.exists(sk_path):
    print(f"Error: {sk_path} not found. Run Client.py once to generate keys.")
    sys.exit(1)
recipient_sk = open(sk_path, "rb").read()

# ---------- IMAP helpers ----------
def imap_login_and_select():
    M = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
    M.login(RECIPIENT_EMAIL, RECIPIENT_APP_PW)
    M.select("INBOX")
    return M

# ---------- Main loop ----------
def main():
    print("[Server] Polling IMAP for QuMail messages...")
    while True:
        try:
            M = imap_login_and_select()
        except Exception as e:
            print("[Server] IMAP login error:", e)
            time.sleep(CHECK_INTERVAL)
            continue

        typ, data = M.search(None, 'SUBJECT', '"QuMail:"')
        if typ != "OK" or not data[0]:
            M.logout()
            time.sleep(CHECK_INTERVAL)
            continue

        last_id = data[0].split()[-1]
        typ, msg_data = M.fetch(last_id, "(RFC822)")
        raw = msg_data[0][1]
        msg = email.message_from_bytes(raw)

        body = None
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_payload(decode=True).decode()
                    break
        else:
            body = msg.get_payload(decode=True).decode()

        # Extract base64 payload
        b64_payload = body.strip().splitlines()[-1]
        payload = json.loads(base64.b64decode(b64_payload).decode())

        capsule = base64.b64decode(payload["capsule_b64"])
        nonce = base64.b64decode(payload["nonce_b64"])
        tag = base64.b64decode(payload["tag_b64"])
        cipher = base64.b64decode(payload["cipher_b64"])

        shared_secret = Kyber768.dec(capsule, recipient_sk)
        aes_key = derive_aes_key_from_shared_secret(shared_secret)
        print("[Server] AES_KEY_HEX (derived):", aes_key.hex())

        plaintext = aes_gcm_decrypt(aes_key, nonce, cipher, tag)

        # Write to HTML file
        out_file = f"decrypted_{payload['id']}.html"
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(f"<html><body><h2>Decrypted QuMail message</h2><pre>{plaintext.decode(errors='replace')}</pre></body></html>")

        print(f"[Server] Message decrypted and saved to {out_file}")
        M.logout()
        break

if __name__ == "__main__":
    main()

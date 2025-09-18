# Client.py
import os
import sys
import base64
import uuid
import smtplib
import json
from email.message import EmailMessage
from hashlib import sha256
from Crypto.Cipher import AES  # pip install pycryptodome
from Crypto.Random import get_random_bytes

# Import your Kyber stub
from kyber import Kyber768

# ---------- Helpers ----------
def derive_aes_key_from_shared_secret(shared_secret_bytes, info=b"qumail-aes-key", length=32):
    return sha256(shared_secret_bytes + info).digest()[:length]

def aes_gcm_encrypt(key, plaintext_bytes):
    nonce = get_random_bytes(12)  # recommended 12 bytes
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
    return nonce, ciphertext, tag

# ---------- Config ----------
SENDER_EMAIL = os.environ.get("QUMAIL_SENDER_EMAIL", "shubhamhiremath87@gmail.com")
SENDER_APP_PW = os.environ.get("QUMAIL_SENDER_APP_PASSWORD", "hagusyzrlycazzcy")
SMTP_HOST = os.environ.get("QUMAIL_SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("QUMAIL_SMTP_PORT", 587))
RECIPIENT_EMAIL = os.environ.get("QUMAIL_RECIPIENT_EMAIL", "shreyaskatti007@gmail.com")

if not (SENDER_EMAIL and SENDER_APP_PW and RECIPIENT_EMAIL):
    print("Please set env vars: QUMAIL_SENDER_EMAIL, QUMAIL_SENDER_APP_PASSWORD, QUMAIL_RECIPIENT_EMAIL")
    sys.exit(1)

# ---------- main ----------
def main():
    pk_path = "recipient_pk.bin"
    sk_path = "recipient_sk.bin"
    if not os.path.exists(pk_path) or not os.path.exists(sk_path):
        # Generate recipient keypair if missing
        pk, sk = Kyber768.keygen()
        with open(pk_path, "wb") as f: f.write(pk)
        with open(sk_path, "wb") as f: f.write(sk)
        print("[Client] Generated recipient_pk.bin and recipient_sk.bin")

    recipient_pk = open(pk_path, "rb").read()

    print("Enter message to send (end with Ctrl+Z or Ctrl+D):")
    plaintext = sys.stdin.read().encode("utf-8")
    if not plaintext:
        print("No plaintext provided. Exiting.")
        return

    # KEM encapsulation
    capsule, shared_secret = Kyber768.enc(recipient_pk)
    aes_key = derive_aes_key_from_shared_secret(shared_secret)
    print("[Client] AES_KEY_HEX (demo):", aes_key.hex())

    # AES-GCM encrypt
    nonce, ciphertext, tag = aes_gcm_encrypt(aes_key, plaintext)

    # Build payload
    msg_id = uuid.uuid4().hex[:8]
    payload_obj = {
        "id": msg_id,
        "capsule_b64": base64.b64encode(capsule).decode(),
        "nonce_b64": base64.b64encode(nonce).decode(),
        "tag_b64": base64.b64encode(tag).decode(),
        "cipher_b64": base64.b64encode(ciphertext).decode()
    }
    payload_b64 = base64.b64encode(json.dumps(payload_obj).encode()).decode()

    # Send via SMTP
    subject = f"QuMail:{msg_id}"
    em = EmailMessage()
    em["From"] = SENDER_EMAIL
    em["To"] = RECIPIENT_EMAIL
    em["Subject"] = subject
    em.set_content("QuMail encrypted payload (base64)\n\n" + payload_b64)

    print(f"[Client] Connecting to SMTP {SMTP_HOST}:{SMTP_PORT} ...")
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        s.starttls()
        s.login(SENDER_EMAIL, SENDER_APP_PW)
        s.send_message(em)

    print(f"[Client] Sent encrypted email to {RECIPIENT_EMAIL} with subject {subject}.")

if __name__ == "__main__":
    main()

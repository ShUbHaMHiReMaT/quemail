# decrypt_local.py
import base64
import binascii
import glob
import os
from Crypto.Cipher import AES


RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")


def find_latest_b64_file():
    """Finds the newest .b64 file in results/"""
    files = glob.glob(os.path.join(RESULTS_DIR, "*.b64"))
    if not files:
        raise FileNotFoundError("No .b64 files found in results/ folder")
    return max(files, key=os.path.getmtime)


def decrypt_blob_file(b64_path: str, aes_key_hex: str) -> str:
    """Decrypts a base64 AES-GCM blob from file using given key hex."""
    key = binascii.unhexlify(aes_key_hex.strip())
    blob_b64 = open(b64_path, "r", encoding="utf-8").read().strip()
    data = base64.b64decode(blob_b64)

    if len(data) < 32:
        raise ValueError("Ciphertext too short (needs nonce+tag+ciphertext)")

    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode("utf-8", errors="replace")


if __name__ == "__main__":
    print("=== QuMail Local Decrypt Tool ===")

    try:
        latest_file = find_latest_b64_file()
        print(f"Latest encrypted file found: {latest_file}")
    except Exception as e:
        print("❌ Error:", e)
        exit(1)

    aes_key_hex = input("Enter AES_KEY_HEX (from Client debug output): ").strip()

    try:
        message = decrypt_blob_file(latest_file, aes_key_hex)
        print("\n✅ Decrypted plaintext message:")
        print("--------------------------------")
        print(message)
        print("--------------------------------")
    except Exception as e:
        print("❌ Decryption failed:", e)

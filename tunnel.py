# tunnel.py
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import socket

def derive_key(shared_secret):
    """Derives a 256-bit key from the shared secret using SHA-256."""
    return hashlib.sha256(shared_secret).digest()

def encrypt(data, key):
    """
    Encrypts and authenticates data using AES-256 in GCM mode.
    """
    cipher = AES.new(key, AES.MODE_GCM)
    encrypted_data, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + encrypted_data

def decrypt(data, key):
    """
    Decrypts and verifies data using AES-256 in GCM mode.
    Raises a ValueError if the data has been tampered with.
    """
    nonce = data[:16]
    tag = data[16:32]
    encrypted_data = data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)
    return decrypted_data

def forward_traffic(source, destination, shared_secret):
    """
    Reads from source, encrypts/decrypts, and writes to destination.
    """
    key = derive_key(shared_secret)
    is_encrypting = "127.0.0.1" in str(source.getpeername())

    while True:
        try:
            data = source.recv(4096)
            if not data:
                break
            
            if is_encrypting:
                processed_data = encrypt(data, key)
            else:
                try:
                    processed_data = decrypt(data, key)
                except ValueError:
                    print("[!] SECURITY ALERT: Message authentication failed! Data may have been tampered with. Closing connection.")
                    break

            destination.sendall(processed_data)
        except (ConnectionResetError, BrokenPipeError, OSError):
            break
        except Exception as e:
            print(f"[Error] Error in forward_traffic: {e}")
            break
            
    try:
        source.close()
    except:
        pass
    try:
        destination.close()
    except:
        pass
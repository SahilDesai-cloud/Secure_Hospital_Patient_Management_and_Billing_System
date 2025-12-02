from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from config import get_aes_key


def encrypt_value(plaintext: str) -> str:
    """Encrypt text with AES-256-GCM and return base64 string."""
    key = get_aes_key()
    data = plaintext.encode("utf-8")
    iv = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return b64encode(iv + tag + ciphertext).decode("utf-8")


def decrypt_value(enc: str) -> str:
    """Decrypt base64 string that was encrypted with encrypt_value."""
    key = get_aes_key()
    raw = b64decode(enc)
    iv = raw[:12]
    tag = raw[12:28]
    ciphertext = raw[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data.decode("utf-8")

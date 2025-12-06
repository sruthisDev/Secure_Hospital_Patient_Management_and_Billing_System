import os
from base64 import b64decode, b64encode

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import get_aes_key


def encrypt_value(plaintext: str) -> str:
    """Encrypt text with AES-256-GCM and return base64 string."""
    key = get_aes_key()
    data = plaintext.encode("utf-8")
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, data, None)
    return b64encode(iv + ciphertext).decode("utf-8")


def decrypt_value(enc: str) -> str:
    """Decrypt base64 string that was encrypted with encrypt_value."""
    key = get_aes_key()
    raw = b64decode(enc)
    iv = raw[:12]
    ciphertext = raw[12:]
    aesgcm = AESGCM(key)
    data = aesgcm.decrypt(iv, ciphertext, None)
    return data.decode("utf-8")

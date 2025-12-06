import os
import secrets
from typing import Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

try:
    import mysql.connector
except ModuleNotFoundError:
    raise RuntimeError("Missing dependency 'mysql-connector-python'. Run `pip install -r requirements.txt` to install required packages.")


# Persisted key file keeps encryption stable across restarts if env var is not set.
KEY_FILE = os.environ.get("PII_KEY_FILE", ".encryption_key")


def get_db_conn():
    return mysql.connector.connect(
        host="localhost",
        user=os.environ.get("DB_USER"),
        password=os.environ.get("DB_PASS"),
        database="secure_hospital_db",
    )


def _load_persisted_key() -> Optional[bytes]:
    """Return a 32-byte key from disk if present and valid."""
    if not os.path.exists(KEY_FILE):
        return None
    try:
        with open(KEY_FILE, "rb") as f:
            key_bytes = f.read()
        if len(key_bytes) == 32:
            return key_bytes
    except OSError:
        pass
    return None


def _persist_key(key_bytes: bytes) -> None:
    try:
        with open(KEY_FILE, "wb") as f:
            f.write(key_bytes)
    except OSError:
        # If we cannot persist, warn but still return the key to keep the app working.
        print("Warning: unable to persist AES key to disk; set PII_AES_KEY to avoid data loss.")


def get_aes_key() -> bytes:
    env_key = os.environ.get("PII_AES_KEY")
    if env_key:
        key_bytes = env_key.encode("utf-8")
        if len(key_bytes) != 32:
            raise RuntimeError("AES key must be 32 bytes (after UTF-8 encoding) and set in PII_AES_KEY")
        return key_bytes

    persisted = _load_persisted_key()
    if persisted:
        return persisted

    # Generate a new 32-byte key and persist it for stable encryption across restarts.
    key_bytes = secrets.token_bytes(32)
    _persist_key(key_bytes)
    return key_bytes

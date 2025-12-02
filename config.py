import os
import secrets
try:
    import mysql.connector
except ModuleNotFoundError:
    raise RuntimeError("Missing dependency 'mysql-connector-python'. Run `pip install -r requirements.txt` to install required packages.")


def get_db_conn():
    return mysql.connector.connect(
        host="localhost",
        user=os.environ.get("DB_USER"),
        password=os.environ.get("DB_PASS"),
        database="secure_hospital_db",
    )


def get_aes_key() -> bytes:
    key = os.environ.get("PII_AES_KEY", None)
    # If no key is provided, generate a random 32-byte key for local development.
    # WARNING: this is insecure for production because encrypted data cannot be recovered across restarts.
    if key is None:
        print("Warning: PII_AES_KEY not set — generating a temporary AES key for development.")
        return secrets.token_bytes(32)

    key_bytes = key.encode("utf-8")
    if len(key_bytes) != 32:
        raise RuntimeError("AES key must be 32 bytes (after UTF-8 encoding) and set in PII_AES_KEY")
    return key_bytes

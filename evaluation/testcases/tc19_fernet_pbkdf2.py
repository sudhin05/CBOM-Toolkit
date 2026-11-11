"""Password-based encryption with PBKDF2 and Fernet."""
import base64
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

salt = os.urandom(16)
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)  # expect: PBKDF2-SHA-256
key = base64.urlsafe_b64encode(kdf.derive(b"password"))
token = Fernet(key).encrypt(b"secret")  # expect: AES-128

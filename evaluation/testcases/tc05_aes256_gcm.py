"""AES-256-GCM authenticated encryption."""
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = os.urandom(32)
aead = AESGCM(key)  # expect: AES-256
nonce = os.urandom(12)
ciphertext = aead.encrypt(nonce, b"secret", None)

"""Encrypts uploaded files before storing them."""
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY = AESGCM.generate_key(bit_length=256)


def encrypt_upload(data: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(KEY).encrypt(nonce, data, None)


def content_id(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

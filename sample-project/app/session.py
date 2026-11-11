"""Session cookies signed with HMAC; key exchange for the sync service."""
import hashlib
import hmac

from cryptography.hazmat.primitives.asymmetric import ec

SECRET = b"change-me"


def sign_cookie(value: bytes) -> str:
    return hmac.new(SECRET, value, hashlib.sha256).hexdigest()


def sync_keypair():
    return ec.generate_private_key(ec.SECP256R1())

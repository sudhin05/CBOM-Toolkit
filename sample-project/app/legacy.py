"""Old helpers kept for backwards compatibility."""
import hashlib


def file_checksum(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def gravatar_id(email: str) -> str:
    return hashlib.sha1(email.strip().lower().encode()).hexdigest()

"""SHA-256 digest built incrementally."""
import hashlib


def digest(chunks):
    h = hashlib.sha256()  # expect: SHA-256
    for chunk in chunks:
        h.update(chunk)
    return h.hexdigest()

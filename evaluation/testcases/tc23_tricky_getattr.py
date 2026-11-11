"""TRICKY: crypto reached through getattr and a dynamic import."""
import hashlib
import importlib


def by_name(data, algo="md5"):
    return getattr(hashlib, algo)(data).hexdigest()  # expect: MD5


crypto = importlib.import_module("hashlib")
fingerprint = crypto.sha1(b"x").hexdigest()  # expect: SHA-1

"""MD5 checksum of a file."""
import hashlib


def checksum(path):
    with open(path, "rb") as fh:
        return hashlib.md5(fh.read()).hexdigest()  # expect: MD5

"""TRICKY: algorithm held in a variable, function stored in a variable."""
import hashlib

ALGORITHM = "sha1"


def digest(data):
    return hashlib.new(ALGORITHM, data).hexdigest()  # expect: SHA-1


hasher = hashlib.md5


def legacy(data):
    return hasher(data).hexdigest()  # expect: MD5

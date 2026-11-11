"""TRICKY: algorithm names built at runtime."""
import hashlib

import jwt

version = 1
name = "sha" + str(version)


def digest(data):
    return hashlib.new(name, data).hexdigest()  # expect: SHA-1


def token(payload, key, family="RS"):
    return jwt.encode(payload, key, algorithm=f"{family}256")  # expect: RSA

"""Webhook signatures with HMAC-SHA1."""
import hashlib
import hmac


def sign(key, msg):
    return hmac.new(key, msg, hashlib.sha1).hexdigest()  # expect: HMAC-SHA-1


def sign_bytes(key, msg):
    return hmac.new(key, msg, digestmod="sha1").digest()  # expect: HMAC-SHA-1

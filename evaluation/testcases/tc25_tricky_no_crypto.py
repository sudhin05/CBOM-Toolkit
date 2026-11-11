"""TRICKY: looks like crypto but is not. Talks about RSA and hashlib.md5() in docs."""
import hashlib
from Crypto.Cipher import AES  # imported but never used

# hashlib.md5(b"this line is commented out")
LABEL = "RSA-2048 is mentioned in a string"


def md5(text):
    return text[::-1]


class Registry:
    def new(self, name):
        return name


registry = Registry()
registry.new("sha1")
rsa = Registry()
rsa.new("newkeys")
print(md5("not a hash"))


def fake_hash(hashlib):
    # the parameter shadows the module: this is a test double, not real crypto
    return hashlib.sha1(b"x")

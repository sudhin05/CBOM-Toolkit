"""The same idea written with different import styles."""
from hashlib import sha1 as fingerprint
import hashlib as hl
from Cryptodome.Hash import SHA256

a = fingerprint(b"x").hexdigest()  # expect: SHA-1
b = hl.new("sha512", b"x").hexdigest()  # expect: SHA-512
c = SHA256.new(b"x").hexdigest()  # expect: SHA-256

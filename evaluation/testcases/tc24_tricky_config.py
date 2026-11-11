"""TRICKY: algorithm from the environment, a config file, and a shell command.
config.json (not shown) sets "fingerprint_hash" to "sha1"."""
import hashlib
import json
import os
import subprocess

HASH = os.environ.get("APP_HASH", "md5")


def digest(data):
    return hashlib.new(HASH, data).hexdigest()  # expect: MD5


with open("config.json") as fh:
    CONFIG = json.load(fh)


def fingerprint(data):
    return hashlib.new(CONFIG["fingerprint_hash"], data).hexdigest()  # expect: SHA-1


subprocess.run(["openssl", "genrsa", "-out", "key.pem", "2048"])  # expect: RSA-2048

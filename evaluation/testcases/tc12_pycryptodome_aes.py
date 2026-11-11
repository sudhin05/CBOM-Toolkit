"""AES-256-GCM with pycryptodome."""
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)
cipher = AES.new(key, AES.MODE_GCM)  # expect: AES-256
ciphertext, tag = cipher.encrypt_and_digest(b"secret")

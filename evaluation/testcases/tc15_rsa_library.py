"""The pure-Python rsa package."""
import rsa

(public_key, private_key) = rsa.newkeys(2048)  # expect: RSA-2048
signature = rsa.sign(b"hello", private_key, "SHA-256")  # expect: RSA, SHA-256

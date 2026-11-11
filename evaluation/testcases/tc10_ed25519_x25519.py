"""Ed25519 signing key and an X25519 key exchange."""
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

signer = Ed25519PrivateKey.generate()  # expect: Ed25519
alice = x25519.X25519PrivateKey.generate()  # expect: X25519
bob = x25519.X25519PrivateKey.generate()  # expect: X25519
shared = alice.exchange(bob.public_key())

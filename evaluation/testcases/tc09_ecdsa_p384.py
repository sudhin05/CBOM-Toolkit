"""ECDSA signature on curve P-384."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

key = ec.generate_private_key(ec.SECP384R1())  # expect: EC-P-384
signature = key.sign(b"data", ec.ECDSA(hashes.SHA384()))  # expect: ECDSA, SHA-384

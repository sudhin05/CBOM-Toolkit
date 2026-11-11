"""RSA-3072 signature with PSS padding."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

key = rsa.generate_private_key(public_exponent=65537, key_size=3072)  # expect: RSA-3072
signature = key.sign(
    b"message",
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),  # expect: RSA, SHA-256
                salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256(),  # expect: SHA-256
)

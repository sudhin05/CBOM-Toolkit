"""User login: signs session tokens with an RSA key."""
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_token(user_id):
    return jwt.encode({"sub": user_id}, private_key, algorithm="RS256")


def read_token(token):
    return jwt.decode(token, private_key.public_key(), algorithms=["RS256"])

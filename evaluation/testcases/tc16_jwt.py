"""JSON Web Tokens with PyJWT."""
import jwt

SECRET = "s3cret"
token = jwt.encode({"user": 1}, SECRET)  # expect: HMAC-SHA-256
claims = jwt.decode(token, SECRET, algorithms=["HS256"])  # expect: HMAC-SHA-256


def sign_es256(payload, ec_key):
    return jwt.encode(payload, ec_key, algorithm="ES256")  # expect: ECDSA-P-256


def verify_rs256(token, public_key):
    return jwt.decode(token, public_key, algorithms=["RS256"])  # expect: RSA

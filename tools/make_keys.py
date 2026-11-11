"""Generates the certificate and key files used by the sample project and the
evaluation test set, so they can be re-created at any time:
    python tools/make_keys.py
"""
import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def self_signed(key, common_name, hash_alg):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=730))
            .sign(key, hash_alg))


def write(path, data):
    path = os.path.join(ROOT, path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    print("wrote", os.path.relpath(path, ROOT))


PEM = serialization.Encoding.PEM
PKCS8 = serialization.PrivateFormat.PKCS8
NOENC = serialization.NoEncryption()

# sample project: an RSA-2048 server certificate
rsa2048 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
write("sample-project/certs/server.pem",
      self_signed(rsa2048, "sample.local", hashes.SHA256()).public_bytes(PEM))

# evaluation test set
T = "evaluation/testcases"
rsa3072 = rsa.generate_private_key(public_exponent=65537, key_size=3072)
write(f"{T}/tc26_rsa3072_cert.crt",
      self_signed(rsa3072, "rsa3072.test", hashes.SHA384()).public_bytes(PEM))
p256 = ec.generate_private_key(ec.SECP256R1())
write(f"{T}/tc27_ec_p256_key.key", p256.private_bytes(PEM, PKCS8, NOENC))
ed = ed25519.Ed25519PrivateKey.generate()
write(f"{T}/tc28_ed25519_cert.pem",
      self_signed(ed, "ed25519.test", None).public_bytes(PEM))

# local TLS test server (nginx and python_server.py): RSA-2048, TLS 1.2
server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
write("evaluation/tls-testserver/certs/server.key",
      server_key.private_bytes(PEM, serialization.PrivateFormat.TraditionalOpenSSL, NOENC))
write("evaluation/tls-testserver/certs/server.crt",
      self_signed(server_key, "localhost", hashes.SHA256()).public_bytes(PEM))

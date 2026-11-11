"""Certificate and key scanner: reads .pem/.crt/.cer/.der/.key/.pub files.

For every X.509 certificate it reports two findings:
  * the certificate's public key   (e.g. RSA-2048, EC-P-256)
  * the signature on the certificate (e.g. RSA signed with SHA-256)
For private and public key files it reports the key algorithm and size.
The cryptography library does the parsing; describe_key() is reused by the
TLS checker for the certificate a website sends.
"""

import os
import re

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (dh, dsa, ec, ed448,
                                                       ed25519, rsa, x448,
                                                       x25519)

from .code_scanner import iter_files, relpath
from .code_rules import CURVES
from .finding import make_finding

EXTENSIONS = (".pem", ".crt", ".cer", ".der", ".key", ".pub", ".cert")
PEM_BLOCK = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----", re.S)


def describe_key(key):
    """Return (algorithm, param, primitive) for a public or private key object."""
    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return "RSA", key.key_size, "pke"
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        curve = CURVES.get(key.curve.name.lower(), key.curve.name)
        return "EC", curve, "signature"
    if isinstance(key, (dsa.DSAPublicKey, dsa.DSAPrivateKey)):
        return "DSA", key.key_size, "signature"
    if isinstance(key, (dh.DHPublicKey, dh.DHPrivateKey)):
        return "DH", key.key_size, "key-agree"
    if isinstance(key, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
        return "Ed25519", None, "signature"
    if isinstance(key, (ed448.Ed448PublicKey, ed448.Ed448PrivateKey)):
        return "Ed448", None, "signature"
    if isinstance(key, (x25519.X25519PublicKey, x25519.X25519PrivateKey)):
        return "X25519", None, "key-agree"
    if isinstance(key, (x448.X448PublicKey, x448.X448PrivateKey)):
        return "X448", None, "key-agree"
    # Newer cryptography versions add ML-KEM / ML-DSA key classes.
    name = type(key).__name__
    for pqc in ("MLKEM", "MLDSA", "SLHDSA"):
        if pqc in name.upper():
            return {"MLKEM": "ML-KEM", "MLDSA": "ML-DSA", "SLHDSA": "SLH-DSA"}[pqc], None, \
                "kem" if pqc == "MLKEM" else "signature"
    return name, None, "unknown"


def describe_signature(cert):
    """Return (algorithm, hash name) of the signature on a certificate."""
    oid_name = cert.signature_algorithm_oid._name  # e.g. sha256WithRSAEncryption
    low = oid_name.lower()
    if "rsa" in low:
        alg = "RSA"
    elif "ecdsa" in low:
        alg = "ECDSA"
    elif "dsa" in low:
        alg = "DSA"
    elif "ed25519" in low:
        alg = "Ed25519"
    elif "ed448" in low:
        alg = "Ed448"
    elif "ml-dsa" in low or "mldsa" in low:
        alg = "ML-DSA"
    else:
        alg = oid_name
    h = cert.signature_hash_algorithm
    return alg, (h.name.upper().replace("SHA", "SHA-") if h else None), oid_name


def cert_findings(cert, source, file, line, label_prefix=""):
    """Two findings for one certificate: its key and its signature."""
    subject = cert.subject.rfc4514_string()
    info = {
        "subject": subject,
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "serial": format(cert.serial_number, "x"),
    }
    out = []
    alg, param, prim = describe_key(cert.public_key())
    out.append(make_finding(source, file, line, alg, prim, param, "certificate-key",
                            evidence=f"{label_prefix}certificate key: {subject}",
                            note=f"Certificate expires {info['not_after'][:10]}",
                            extra=info))
    sig_alg, sig_hash, oid_name = describe_signature(cert)
    out.append(make_finding(source, file, line, sig_alg, "signature", None, "certificate-signature",
                            evidence=f"{label_prefix}certificate signature: {oid_name}",
                            note=f"Signature hash: {sig_hash}" if sig_hash else "",
                            extra=info))
    return out


def scan_directory(root):
    findings = []
    for path in iter_files(root, EXTENSIONS):
        findings.extend(scan_file(path, root))
    return findings


def scan_file(path, root=None):
    rel = relpath(path, root)
    with open(path, "rb") as fh:
        data = fh.read()
    blocks = list(PEM_BLOCK.finditer(data))
    if not blocks:
        if data.startswith(b"ssh-") or data.startswith(b"ecdsa-sha2-"):
            return parse_ssh_public(data, rel)
        return parse_der(data, rel)

    findings = []
    for match in blocks:
        line = data.count(b"\n", 0, match.start()) + 1
        kind = match.group(1).decode()
        block = match.group(0)
        try:
            findings.extend(parse_pem_block(kind, block, rel, line))
        except Exception as exc:  # corrupt or unsupported block: report, keep going
            findings.append(make_finding("certificate", rel, line, "Unknown", "unknown",
                                         evidence=f"-----BEGIN {kind}-----",
                                         note=f"Could not parse: {exc}"))
    return findings


def parse_pem_block(kind, block, rel, line):
    if kind in ("CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"):
        return cert_findings(x509.load_pem_x509_certificate(block), "certificate", rel, line)
    if kind == "CERTIFICATE REQUEST":
        csr = x509.load_pem_x509_csr(block)
        alg, param, prim = describe_key(csr.public_key())
        return [make_finding("certificate", rel, line, alg, prim, param, "csr-key",
                             evidence=f"certificate request: {csr.subject.rfc4514_string()}")]
    if kind == "ENCRYPTED PRIVATE KEY":
        return [make_finding("certificate", rel, line, "Unknown", "unknown", None, "private-key",
                             evidence="-----BEGIN ENCRYPTED PRIVATE KEY-----",
                             note="Password-protected key: algorithm cannot be read without the password")]
    if kind == "OPENSSH PRIVATE KEY":
        key = serialization.load_ssh_private_key(block, password=None)
        return [key_finding(key, rel, line, "ssh-private-key", kind)]
    if "PRIVATE KEY" in kind:
        if b"Proc-Type: 4,ENCRYPTED" in block:
            legacy = {"RSA PRIVATE KEY": "RSA", "EC PRIVATE KEY": "EC", "DSA PRIVATE KEY": "DSA"}
            return [make_finding("certificate", rel, line, legacy.get(kind, "Unknown"),
                                 "pke", None, "private-key", evidence=f"-----BEGIN {kind}-----",
                                 note="Password-protected key: size cannot be read")]
        key = serialization.load_pem_private_key(block, password=None)
        return [key_finding(key, rel, line, "private-key", kind)]
    if "PUBLIC KEY" in kind:
        key = serialization.load_pem_public_key(block)
        return [key_finding(key, rel, line, "public-key", kind)]
    if kind == "DH PARAMETERS":
        params = serialization.load_pem_parameters(block)
        return [make_finding("certificate", rel, line, "DH", "key-agree",
                             params.parameter_numbers().p.bit_length(), "parameters",
                             evidence=f"-----BEGIN {kind}-----")]
    return []


def key_finding(key, rel, line, function, kind):
    alg, param, prim = describe_key(key)
    return make_finding("certificate", rel, line, alg, prim, param, function,
                        evidence=f"-----BEGIN {kind}-----")


def parse_ssh_public(data, rel):
    out = []
    for i, raw in enumerate(data.splitlines(), 1):
        raw = raw.strip()
        if not raw or raw.startswith(b"#"):
            continue
        try:
            key = serialization.load_ssh_public_key(raw)
        except Exception:
            continue
        alg, param, prim = describe_key(key)
        out.append(make_finding("certificate", rel, i, alg, prim, param, "ssh-public-key",
                                evidence=raw[:60].decode(errors="replace") + "..."))
    return out


def parse_der(data, rel):
    for loader in (x509.load_der_x509_certificate,):
        try:
            return cert_findings(loader(data), "certificate", rel, 1)
        except Exception:
            pass
    try:
        return [key_finding(serialization.load_der_public_key(data), rel, 1, "public-key", "DER")]
    except Exception:
        pass
    try:
        return [key_finding(serialization.load_der_private_key(data, None), rel, 1,
                            "private-key", "DER")]
    except Exception:
        return []

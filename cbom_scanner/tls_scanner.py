"""TLS checker: connects to a website and records its TLS cryptography.

For one host it reports:
  * every TLS version the server accepts (TLS 1.0/1.1 are yellow)
  * the key exchange of the default connection (ECDHE/X25519 is red,
    a hybrid group such as X25519MLKEM768 is green)
  * the bulk cipher (AES-128 yellow, AES-256 / ChaCha20 green)
  * the server certificate's key and signature algorithm

Python's ssl module does not say which key-exchange group TLS 1.3 used, so
if an `openssl` command is installed we ask it (openssl s_client) for that
one detail. Without openssl the group is reported as "ECDHE (group unknown)".
The scanner does not check whether the certificate is trusted: it only
takes an inventory, so it also works with self-signed test servers.
"""

import re
import shutil
import socket
import ssl
import subprocess
from urllib.parse import urlparse

from cryptography import x509

from .cert_scanner import cert_findings
from .finding import make_finding

TIMEOUT = 6

VERSIONS = [
    ("TLS 1.0", ssl.TLSVersion.TLSv1),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
    ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
]
PY_VERSION_NAMES = {"TLSv1": "TLS 1.0", "TLSv1.1": "TLS 1.1",
                    "TLSv1.2": "TLS 1.2", "TLSv1.3": "TLS 1.3"}

# Key-exchange groups as printed by OpenSSL -> (algorithm, param)
GROUPS = {
    "x25519": ("X25519", None), "x448": ("X448", None),
    "prime256v1": ("ECDHE", "P-256"), "secp256r1": ("ECDHE", "P-256"),
    "p-256": ("ECDHE", "P-256"), "secp384r1": ("ECDHE", "P-384"),
    "p-384": ("ECDHE", "P-384"), "secp521r1": ("ECDHE", "P-521"),
    "p-521": ("ECDHE", "P-521"),
    "x25519mlkem768": ("X25519MLKEM768", None),
    "secp256r1mlkem768": ("SecP256r1MLKEM768", None),
    "secp384r1mlkem1024": ("SecP384r1MLKEM1024", None),
    "mlkem512": ("ML-KEM", 512), "mlkem768": ("ML-KEM", 768), "mlkem1024": ("ML-KEM", 1024),
    "x25519kyber768draft00": ("Kyber", "X25519Kyber768Draft00"),
}


def parse_target(target):
    """'https://example.com:8443/x' -> ('example.com', 8443)"""
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    return parsed.hostname, parsed.port or 443


def permissive_context(version=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if version is not None:
        ctx.minimum_version = version
        ctx.maximum_version = version
        try:  # allow old protocol versions and ciphers so we can detect them
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
    return ctx


def handshake(host, port, ctx):
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return {
                "version": PY_VERSION_NAMES.get(tls.version(), tls.version()),
                "cipher": tls.cipher()[0],
                "cipher_bits": tls.cipher()[2],
                "cert_der": tls.getpeercert(binary_form=True),
            }


def supported_versions(host, port):
    found = []
    for name, version in VERSIONS:
        try:
            handshake(host, port, permissive_context(version))
            found.append(name)
        except (ssl.SSLError, OSError, ValueError):
            pass
    return found


def openssl_group(host, port):
    """Ask the openssl command which key-exchange group was negotiated."""
    exe = shutil.which("openssl")
    if not exe:
        return None, None
    try:
        version = subprocess.run([exe, "version"], capture_output=True, text=True,
                                 timeout=TIMEOUT).stdout.strip()
        result = subprocess.run(
            [exe, "s_client", "-connect", f"{host}:{port}", "-servername", host],
            input="", capture_output=True, text=True, timeout=TIMEOUT * 2)
    except (OSError, subprocess.TimeoutExpired):
        return None, None
    out = result.stdout + result.stderr
    for pattern in (r"Negotiated TLS1\.3 group:\s*(\S+)",
                    r"(?:Server|Peer) Temp Key:\s*([^,\s]+)"):
        match = re.search(pattern, out)
        if match:
            return match.group(1).strip(), version
    return None, version


def describe_cipher(name):
    """'ECDHE-RSA-AES128-GCM-SHA256' or 'TLS_AES_256_GCM_SHA384' ->
    (key exchange or None, bulk algorithm, bulk key bits)."""
    upper = name.upper()
    kex = None
    if not upper.startswith("TLS_"):  # TLS 1.2 and older name the key exchange
        if upper.startswith(("ECDHE", "EECDH")):
            kex = "ECDHE"
        elif upper.startswith(("DHE", "EDH")):
            kex = "DHE"
        elif upper.startswith(("ECDH-",)):
            kex = "ECDH"
        else:
            kex = "RSA"  # e.g. AES128-SHA: RSA key transport
    if "CHACHA20" in upper:
        return kex, "ChaCha20-Poly1305", 256
    match = re.search(r"AES[_-]?(128|256)", upper)
    if match:
        return kex, "AES", int(match.group(1))
    if "3DES" in upper or "DES-CBC3" in upper:
        return kex, "3DES", 168
    if "RC4" in upper:
        return kex, "RC4", 128
    if "CAMELLIA" in upper:
        bits = re.search(r"CAMELLIA[_-]?(128|256)", upper)
        return kex, "Camellia", int(bits.group(1)) if bits else None
    return kex, name, None


def scan_target(target):
    host, port = parse_target(target)
    where = f"{host}:{port}"
    try:
        default = handshake(host, port, permissive_context())
    except (ssl.SSLError, OSError) as exc:
        return [make_finding("tls", where, None, "Unknown", "protocol",
                             evidence=f"connect {where}",
                             note=f"Could not complete a TLS handshake: {exc}")], \
            {"target": where, "error": str(exc)}

    findings = []
    versions = supported_versions(host, port)
    for name in versions:
        note = "Negotiated by default" if name == default["version"] else "Also accepted"
        findings.append(make_finding("tls", where, None, name, "protocol", None, "connect",
                                     evidence=f"server accepts {name}", note=note))

    kex, bulk, bits = describe_cipher(default["cipher"])
    group, openssl_version = openssl_group(host, port)
    if group:
        alg, param = GROUPS.get(group.lower(), (group, None))
        note = f"Group reported by {openssl_version}"
        if "MLKEM" not in group.upper() and openssl_version and \
                not openssl_supports_mlkem(openssl_version):
            note += ("; this OpenSSL cannot offer ML-KEM, so a hybrid post-quantum group "
                     "would not be negotiated even if the server supports it")
    elif kex:
        alg, param, note = kex, None, "From the TLS 1.2 cipher suite name"
    else:
        alg, param = "ECDHE", None
        note = "TLS 1.3 group not visible to Python's ssl module and no openssl found"
    if kex == "RSA":
        alg, param, note = "RSA", None, "RSA key transport (no forward secrecy)"
    findings.append(make_finding("tls", where, None, alg, "key-agree", param, "keyexchange",
                                 evidence=f"cipher suite {default['cipher']}", note=note))

    findings.append(make_finding("tls", where, None, bulk, "ae", bits, "encrypt",
                                 evidence=f"cipher suite {default['cipher']}",
                                 note=f"Bulk encryption of {default['version']} session"))

    cert = x509.load_der_x509_certificate(default["cert_der"])
    findings.extend(cert_findings(cert, "tls", where, None, label_prefix="server "))

    summary = {"target": where, "default_version": default["version"],
               "cipher": default["cipher"], "versions": versions,
               "group": group, "openssl": openssl_version}
    return findings, summary


def openssl_supports_mlkem(version_text):
    match = re.search(r"OpenSSL (\d+)\.(\d+)", version_text or "")
    return bool(match) and (int(match.group(1)), int(match.group(2))) >= (3, 5)


def scan_targets(targets):
    findings, summaries = [], []
    for target in targets:
        f, s = scan_target(target)
        findings.extend(f)
        summaries.append(s)
    return findings, summaries

"""Dependency checker: lists crypto libraries in requirements*.txt and pyproject.toml.

A library is not an algorithm, so these findings get the label "info" and are
not counted in the readiness score. They still go into the CBOM as
"library" components, and the note says which algorithms the library offers.
"""

import ast
import os
import re
import tomllib

from .code_scanner import SKIP_DIRS, relpath
from .finding import make_finding

# PyPI name (lower case, "_" -> "-") -> what it provides
CRYPTO_LIBRARIES = {
    "cryptography": "General-purpose: RSA, EC, Ed25519, AES, ChaCha20, hashes, X.509",
    "pycryptodome": "General-purpose: RSA, DSA, ECC, AES, DES, 3DES, RC4, hashes",
    "pycryptodomex": "General-purpose (Cryptodome namespace): RSA, ECC, AES, hashes",
    "pycrypto": "Unmaintained since 2013 with known vulnerabilities; replace with pycryptodome",
    "rsa": "Pure-Python RSA only (quantum-vulnerable)",
    "ecdsa": "Pure-Python ECDSA/EdDSA only (quantum-vulnerable)",
    "pyjwt": "JSON Web Tokens: HMAC, RSA and ECDSA signatures",
    "python-jose": "JSON Web Tokens/Encryption: HMAC, RSA, ECDSA, AES",
    "jwcrypto": "JOSE (JWT/JWE/JWS): RSA, ECDSA, AES",
    "authlib": "OAuth/JOSE: RSA, ECDSA, HMAC signatures",
    "paramiko": "SSH: RSA, ECDSA, Ed25519 keys; ECDH/DH key exchange",
    "asyncssh": "SSH: RSA, ECDSA, Ed25519 keys; ECDH/DH key exchange",
    "pyopenssl": "OpenSSL bindings: TLS, X.509, RSA, EC",
    "pynacl": "libsodium: X25519, Ed25519, XSalsa20-Poly1305",
    "bcrypt": "Password hashing (bcrypt)",
    "passlib": "Password hashing: bcrypt, PBKDF2, argon2, legacy MD5-crypt",
    "argon2-cffi": "Password hashing (Argon2)",
    "m2crypto": "OpenSSL bindings: RSA, EC, TLS, X.509",
    "tlslite-ng": "Pure-Python TLS",
    "itsdangerous": "Signed tokens using HMAC (SHA-1 by default)",
    "liboqs-python": "Post-quantum: ML-KEM, ML-DSA, SLH-DSA (liboqs)",
    "oqs": "Post-quantum: ML-KEM, ML-DSA, SLH-DSA (liboqs)",
    "pqcrypto": "Post-quantum algorithms",
    "certifi": "CA certificate bundle",
    "pyotp": "One-time passwords (HMAC-SHA1 by default)",
    "hashids": "Not encryption (reversible encoding)",
    "keyring": "OS credential storage",
    "gnupg": "OpenPGP via GnuPG: RSA, EC",
    "python-gnupg": "OpenPGP via GnuPG: RSA, EC",
}

REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirement(text):
    """'cryptography>=41.0 ; python_version>"3.8"' -> ('cryptography', '>=41.0')"""
    text = text.split(";")[0].split("#")[0].strip()
    match = REQ_LINE.match(text)
    if not match:
        return None, None
    return match.group(1), match.group(3).strip() or None


def scan_directory(root):
    findings = []
    if os.path.isfile(root):
        return findings
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            lower = name.lower()
            if "requirements" in lower and lower.endswith(".txt"):
                findings.extend(scan_requirements(path, root))
            elif lower == "pyproject.toml":
                findings.extend(scan_pyproject(path, root))
            elif lower == "setup.py":
                findings.extend(scan_setup_py(path, root))
    return dedupe(findings)


def dedupe(findings):
    """Keep one finding per (file, package): a library listed in several
    dependency groups of the same file is still one dependency."""
    seen, out = set(), []
    for f in findings:
        key = (f["file"], f["extra"]["package"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def make_dep(name, version, file, line, text):
    key = normalize(name)
    note = CRYPTO_LIBRARIES[key]
    if version is None:
        note += ". Version not pinned"
    return make_finding("dependency", file, line, key, "library", param=None,
                        function=None, evidence=text.strip(), note=note,
                        extra={"package": key, "version": version})


def scan_requirements(path, root):
    rel = relpath(path, root)
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "-")):
                continue  # comments and options such as -r other.txt
            name, version = parse_requirement(stripped)
            if name and normalize(name) in CRYPTO_LIBRARIES:
                out.append(make_dep(name, version, rel, lineno, stripped))
    return out


def scan_pyproject(path, root):
    rel = relpath(path, root)
    with open(path, "rb") as fh:
        try:
            data = tomllib.load(fh)
        except tomllib.TOMLDecodeError:
            return []
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.read().splitlines()

    specs = []  # (name, version, raw text)
    project = data.get("project", {})
    for item in project.get("dependencies", []):
        specs.append((*parse_requirement(item), item))
    for group in project.get("optional-dependencies", {}).values():
        for item in group:
            specs.append((*parse_requirement(item), item))
    for group in data.get("dependency-groups", {}).values():
        for item in group:
            if isinstance(item, str):
                specs.append((*parse_requirement(item), item))
    poetry = data.get("tool", {}).get("poetry", {})
    tables = [poetry.get("dependencies", {}), poetry.get("dev-dependencies", {})]
    tables += [g.get("dependencies", {}) for g in poetry.get("group", {}).values()]
    for table in tables:
        for name, value in table.items():
            version = value if isinstance(value, str) else (value or {}).get("version")
            specs.append((name, version, f"{name} = {value!r}"))

    out = []
    for name, version, raw in specs:
        if name and normalize(name) in CRYPTO_LIBRARIES:
            out.append(make_dep(name, version, rel, find_line(lines, name), raw))
    return out


def find_line(lines, name):
    pattern = re.compile(r"""(^|["'\s])""" + re.escape(name) + r"""(\s|[<>=!~\[;"']|$)""", re.I)
    for i, line in enumerate(lines, 1):
        if pattern.search(line):
            return i
    return None


def scan_setup_py(path, root):
    """Read install_requires=[...] and extras_require={...} from setup.py
    (only literal lists of strings; setup.py is parsed, never executed)."""
    rel = relpath(path, root)
    with open(path, encoding="utf-8", errors="replace") as fh:
        source = fh.read()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    out = []

    def strings(node):
        if isinstance(node, (ast.List, ast.Tuple)):
            for elt in node.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    yield elt.value, elt.lineno
        elif isinstance(node, ast.Dict):
            for value in node.values:
                yield from strings(value)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg in ("install_requires", "extras_require", "tests_require"):
                    for text, lineno in strings(kw.value):
                        name, version = parse_requirement(text)
                        if name and normalize(name) in CRYPTO_LIBRARIES:
                            out.append(make_dep(name, version, rel, lineno, text))
    return out

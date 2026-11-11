"""The labelling rules: which algorithm gets red, yellow or green.

    red    -- broken by a quantum computer (Shor's algorithm):
              RSA, DSA, Diffie-Hellman and all elliptic-curve schemes.
    yellow -- weak today, or weakened by a quantum computer (Grover's
              algorithm halves the security of symmetric keys and hashes):
              MD5, SHA-1, AES-128, DES, 3DES, RC4, old TLS versions ...
    green  -- considered quantum-safe: AES-192/256, SHA-256 and above,
              SHA-3, ChaCha20, ML-KEM, ML-DSA, SLH-DSA ...
    info   -- not an algorithm (a crypto library found in requirements.txt);
              listed in the CBOM but not counted in the readiness score.

The table is deliberately small so it can be read and defended in a viva.
"""

# --- Public-key algorithms that Shor's algorithm breaks completely ----------
RED = {
    "RSA", "DSA", "DH", "EC", "ECDSA", "ECDH", "ECDHE", "EdDSA",
    "Ed25519", "Ed448", "X25519", "X448", "DHE",
}

# --- Weak today (classically broken or deprecated) --------------------------
YELLOW = {
    "MD2", "MD4", "MD5", "SHA-1", "SHA-224", "SHA3-224", "SHAKE128", "RIPEMD-160",
    "DES", "3DES", "RC2", "RC4", "Blowfish", "CAST5", "IDEA", "SEED",
    "SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1",
    "NULL",
}

# --- Quantum-safe today ------------------------------------------------------
GREEN = {
    "SHA-256", "SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256",
    "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE256",
    "BLAKE2b", "BLAKE2s", "SM3",
    "ChaCha20", "ChaCha20-Poly1305", "XSalsa20-Poly1305",
    "ML-KEM", "ML-DSA", "SLH-DSA", "FN-DSA", "Falcon",
    "Kyber", "Dilithium", "SPHINCS+",
    "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024",
    "TLS 1.2", "TLS 1.3",
    "PBKDF2", "scrypt", "Argon2", "bcrypt", "HKDF",
}

# Hash name inside HMAC-<hash> decides the label of the HMAC.
# AES and similar ciphers are labelled by key size.
SIZED_SYMMETRIC = {"AES", "Camellia", "ARIA", "SM4"}


def classify(algorithm, param=None, primitive=None):
    """Return (label, reason) for one algorithm."""
    if primitive == "library":
        return "info", "Crypto library dependency (see code findings for how it is used)"

    if algorithm == "SSH":
        return "red", "SSH session with classical key exchange (ECDH/DH), broken by Shor's algorithm"

    if algorithm in RED:
        return "red", "Public-key algorithm broken by Shor's algorithm on a quantum computer"

    # HMAC-SHA256 -> look at SHA-256
    if algorithm.startswith("HMAC-"):
        inner, _ = classify(algorithm[5:], None, "hash")
        if inner == "green":
            return "green", "HMAC with a strong hash stays secure against quantum attacks"
        return "yellow", "HMAC built on a weak hash; move to HMAC-SHA256 or better"

    if algorithm in SIZED_SYMMETRIC:
        if isinstance(param, int):
            if param >= 192:
                return "green", f"{param}-bit symmetric key keeps >= 96-bit security under Grover's algorithm"
            return "yellow", f"{param}-bit key is halved to {param // 2}-bit security by Grover's algorithm; use 256-bit"
        return "yellow", "Key size could not be determined; use a 256-bit key to be quantum-safe"

    if algorithm in YELLOW:
        if algorithm.startswith(("TLS", "SSL")):
            return "yellow", "Deprecated protocol version; use TLS 1.2 or 1.3"
        if algorithm in ("MD2", "MD4", "MD5", "SHA-1", "RIPEMD-160"):
            return "yellow", "Hash is broken or weak today (collisions); use SHA-256 or SHA-3"
        if algorithm in ("SHA-224", "SHA3-224", "SHAKE128"):
            return "yellow", "Only 112-bit collision resistance, reduced further by quantum attacks"
        return "yellow", "Weak or deprecated cipher; use AES-256 or ChaCha20"

    if algorithm == "TLS":
        return "yellow", ("TLS with library defaults: the key exchange is classical (ECDHE) "
                          "unless a hybrid ML-KEM group is negotiated")

    for prefix in ("ML-KEM", "ML-DSA", "SLH-DSA", "Kyber", "Dilithium", "Falcon", "SPHINCS+"):
        if algorithm.startswith(prefix):
            return "green", "NIST post-quantum algorithm"
    if "MLKEM" in algorithm:
        return "green", "Hybrid key exchange with ML-KEM (post-quantum)"

    if algorithm in GREEN:
        if algorithm.startswith("TLS"):
            return "green", "Current protocol version (check its key exchange separately)"
        return "green", "Considered quantum-safe with current key and output sizes"

    return "yellow", "Unknown algorithm; review by hand"


# NIST post-quantum security level (0 = broken by quantum computers),
# written into the CycloneDX CBOM field nistQuantumSecurityLevel.
def nist_quantum_level(algorithm, param=None):
    if algorithm in RED:
        return 0
    table = {
        "SHA-256": 2, "SHA3-256": 2, "SHA-384": 4, "SHA3-384": 4,
        "SHA-512": 5, "SHA3-512": 5, "ChaCha20": 5, "ChaCha20-Poly1305": 5,
        "MD5": 0, "SHA-1": 0, "MD4": 0, "DES": 0, "3DES": 0, "RC4": 0,
        "ML-KEM-512": 1, "ML-KEM-768": 3, "ML-KEM-1024": 5,
        "ML-DSA-44": 2, "ML-DSA-65": 3, "ML-DSA-87": 5,
    }
    key = algorithm if param is None else f"{algorithm}-{param}"
    if key in table:
        return table[key]
    if algorithm in table:
        return table[algorithm]
    if algorithm == "AES" and isinstance(param, int):
        return {128: 1, 192: 3, 256: 5}.get(param)
    return None

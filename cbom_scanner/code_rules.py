"""The rules file: which Python function call means which algorithm.

Each key is the *fully qualified* name of a function or class, after import
aliases have been resolved by the code scanner. For example both
    import hashlib;               hashlib.md5()
    from hashlib import md5 as m; m()
resolve to "hashlib.md5".

Each value says what to report:
    alg      algorithm name (see rules.py for its red/yellow/green label)
    prim     CycloneDX primitive (hash, mac, block-cipher, pke, signature,
             key-agree, kem, kdf, ae, stream-cipher, protocol)
    fn       crypto function (digest, keygen, encrypt, sign, ...)
    size     where the key size in bits is: (position, keyword_name)
    keybytes where the raw key is (its length gives the key size)
    curve    where the elliptic curve is
    param    a fixed parameter (e.g. Fernet always uses AES-128)
    hash_arg where a hash name is given (reported as a second finding)
    handler  name of a special function in code_scanner.py for calls whose
             algorithm is given as a string (hashlib.new("md5"), JWT, ...)

To support a new library, add lines here; the scanner itself does not change.
"""

CRYPTO = "cryptography.hazmat.primitives"
DECREPIT = "cryptography.hazmat.decrepit.ciphers.algorithms"

RULES = {}


def rule(names, **spec):
    for name in names if isinstance(names, (list, tuple)) else [names]:
        RULES[name] = spec


# --------------------------------------------------------------------------
# hashlib and hmac (Python standard library)
# --------------------------------------------------------------------------
for fn, alg in {
    "md5": "MD5", "sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256",
    "sha384": "SHA-384", "sha512": "SHA-512", "sha3_224": "SHA3-224",
    "sha3_256": "SHA3-256", "sha3_384": "SHA3-384", "sha3_512": "SHA3-512",
    "blake2b": "BLAKE2b", "blake2s": "BLAKE2s",
    "shake_128": "SHAKE128", "shake_256": "SHAKE256",
}.items():
    rule(f"hashlib.{fn}", alg=alg, prim="hash", fn="digest")

rule("hashlib.new", handler="hash_by_name", arg=(0, "name"))
rule("hashlib.file_digest", handler="hash_by_name", arg=(1, "digest"))
rule("hashlib.pbkdf2_hmac", handler="pbkdf2_by_name", arg=(0, "hash_name"))
rule("hashlib.scrypt", alg="scrypt", prim="kdf", fn="keyderive")
rule(["hmac.new", "hmac.HMAC"], handler="hmac", arg=(2, "digestmod"))
rule("hmac.digest", handler="hmac", arg=(2, "digest"))

# --------------------------------------------------------------------------
# cryptography (pyca)
# --------------------------------------------------------------------------
for cls, alg in {
    "MD5": "MD5", "SHA1": "SHA-1", "SHA224": "SHA-224", "SHA256": "SHA-256",
    "SHA384": "SHA-384", "SHA512": "SHA-512", "SHA512_224": "SHA-512/224",
    "SHA512_256": "SHA-512/256", "SHA3_224": "SHA3-224", "SHA3_256": "SHA3-256",
    "SHA3_384": "SHA3-384", "SHA3_512": "SHA3-512", "BLAKE2b": "BLAKE2b",
    "BLAKE2s": "BLAKE2s", "SHAKE128": "SHAKE128", "SHAKE256": "SHAKE256",
    "SM3": "SM3",
}.items():
    rule(f"{CRYPTO}.hashes.{cls}", alg=alg, prim="hash", fn="digest")

rule(f"{CRYPTO}.asymmetric.rsa.generate_private_key",
     alg="RSA", prim="pke", fn="keygen", size=(1, "key_size"))
rule(f"{CRYPTO}.asymmetric.padding.OAEP", alg="RSA", prim="pke", fn="encrypt")
rule(f"{CRYPTO}.asymmetric.padding.PSS", alg="RSA", prim="signature", fn="sign")
rule(f"{CRYPTO}.asymmetric.padding.PKCS1v15", alg="RSA", prim="signature", fn="sign")
rule(f"{CRYPTO}.asymmetric.dsa.generate_private_key",
     alg="DSA", prim="signature", fn="keygen", size=(0, "key_size"))
rule(f"{CRYPTO}.asymmetric.dsa.generate_parameters",
     alg="DSA", prim="signature", fn="keygen", size=(0, "key_size"))
rule(f"{CRYPTO}.asymmetric.dh.generate_parameters",
     alg="DH", prim="key-agree", fn="keygen", size=(1, "key_size"))
rule(f"{CRYPTO}.asymmetric.ec.generate_private_key",
     alg="EC", prim="signature", fn="keygen", curve=(0, "curve"))
rule(f"{CRYPTO}.asymmetric.ec.derive_private_key",
     alg="EC", prim="signature", fn="keygen", curve=(1, "curve"))
rule(f"{CRYPTO}.asymmetric.ec.ECDSA", alg="ECDSA", prim="signature", fn="sign")
rule(f"{CRYPTO}.asymmetric.ec.ECDH", alg="ECDH", prim="key-agree", fn="keyagree")
for mod, cls, alg, prim in [
    ("ed25519", "Ed25519PrivateKey", "Ed25519", "signature"),
    ("ed448", "Ed448PrivateKey", "Ed448", "signature"),
    ("x25519", "X25519PrivateKey", "X25519", "key-agree"),
    ("x448", "X448PrivateKey", "X448", "key-agree"),
]:
    rule(f"{CRYPTO}.asymmetric.{mod}.{cls}.generate", alg=alg, prim=prim, fn="keygen")
    rule(f"{CRYPTO}.asymmetric.{mod}.{cls}.from_private_bytes", alg=alg, prim=prim, fn="keygen")

ALG = f"{CRYPTO}.ciphers.algorithms"
rule(f"{ALG}.AES", alg="AES", prim="block-cipher", fn="encrypt", keybytes=(0, "key"))
rule(f"{ALG}.AES128", alg="AES", prim="block-cipher", fn="encrypt", param=128)
rule(f"{ALG}.AES256", alg="AES", prim="block-cipher", fn="encrypt", param=256)
rule(f"{ALG}.Camellia", alg="Camellia", prim="block-cipher", fn="encrypt", keybytes=(0, "key"))
rule(f"{ALG}.ChaCha20", alg="ChaCha20", prim="stream-cipher", fn="encrypt")
rule(f"{ALG}.SM4", alg="SM4", prim="block-cipher", fn="encrypt", param=128)
for cls, alg in {"TripleDES": "3DES", "ARC4": "RC4", "Blowfish": "Blowfish",
                 "CAST5": "CAST5", "IDEA": "IDEA", "SEED": "SEED", "RC2": "RC2"}.items():
    rule([f"{ALG}.{cls}", f"{DECREPIT}.{cls}"], alg=alg, prim="block-cipher", fn="encrypt")

AEAD = f"{CRYPTO}.ciphers.aead"
for cls in ("AESGCM", "AESCCM", "AESOCB3", "AESSIV", "AESGCMSIV"):
    rule(f"{AEAD}.{cls}", alg="AES", prim="ae", fn="encrypt", keybytes=(0, "key"))
    rule(f"{AEAD}.{cls}.generate_key", alg="AES", prim="ae", fn="keygen", size=(0, "bit_length"))
rule(f"{AEAD}.ChaCha20Poly1305", alg="ChaCha20-Poly1305", prim="ae", fn="encrypt")

rule("cryptography.fernet.Fernet", alg="AES", prim="ae", fn="encrypt", param=128,
     note="Fernet always uses AES-128-CBC with HMAC-SHA256")
rule(f"{CRYPTO}.hmac.HMAC", handler="hmac", arg=(1, "algorithm"))
rule(f"{CRYPTO}.kdf.pbkdf2.PBKDF2HMAC", handler="kdf_with_hash", alg="PBKDF2", arg=(0, "algorithm"))
rule(f"{CRYPTO}.kdf.hkdf.HKDF", handler="kdf_with_hash", alg="HKDF", arg=(0, "algorithm"))
rule(f"{CRYPTO}.kdf.scrypt.Scrypt", alg="scrypt", prim="kdf", fn="keyderive")

# --------------------------------------------------------------------------
# pycryptodome  (package "Crypto"; pycryptodomex uses "Cryptodome", which
# the scanner rewrites to "Crypto" before looking up a rule)
# --------------------------------------------------------------------------
for mod, alg in {"MD2": "MD2", "MD4": "MD4", "MD5": "MD5", "SHA1": "SHA-1",
                 "SHA": "SHA-1", "SHA224": "SHA-224", "SHA256": "SHA-256",
                 "SHA384": "SHA-384", "SHA512": "SHA-512",
                 "SHA3_256": "SHA3-256", "SHA3_384": "SHA3-384",
                 "SHA3_512": "SHA3-512", "BLAKE2b": "BLAKE2b",
                 "BLAKE2s": "BLAKE2s", "RIPEMD160": "RIPEMD-160"}.items():
    rule(f"Crypto.Hash.{mod}.new", alg=alg, prim="hash", fn="digest")
rule("Crypto.Hash.HMAC.new", handler="hmac", arg=(2, "digestmod"))
rule("Crypto.Cipher.AES.new", alg="AES", prim="block-cipher", fn="encrypt", keybytes=(0, "key"))
for mod, alg in {"DES": "DES", "DES3": "3DES", "ARC4": "RC4", "ARC2": "RC2",
                 "Blowfish": "Blowfish", "CAST": "CAST5"}.items():
    rule(f"Crypto.Cipher.{mod}.new", alg=alg, prim="block-cipher", fn="encrypt")
rule("Crypto.Cipher.ChaCha20.new", alg="ChaCha20", prim="stream-cipher", fn="encrypt")
rule("Crypto.Cipher.ChaCha20_Poly1305.new", alg="ChaCha20-Poly1305", prim="ae", fn="encrypt")
rule("Crypto.Cipher.PKCS1_OAEP.new", alg="RSA", prim="pke", fn="encrypt")
rule("Crypto.Cipher.PKCS1_v1_5.new", alg="RSA", prim="pke", fn="encrypt")
rule(["Crypto.Signature.pkcs1_15.new", "Crypto.Signature.pss.new",
      "Crypto.Signature.PKCS1_v1_5.new", "Crypto.Signature.PKCS1_PSS.new"],
     alg="RSA", prim="signature", fn="sign")
rule("Crypto.PublicKey.RSA.generate", alg="RSA", prim="pke", fn="keygen", size=(0, "bits"))
rule("Crypto.PublicKey.DSA.generate", alg="DSA", prim="signature", fn="keygen", size=(0, "bits"))
rule("Crypto.PublicKey.ECC.generate", alg="EC", prim="signature", fn="keygen", curve=(None, "curve"))
rule("Crypto.Protocol.KDF.PBKDF2", alg="PBKDF2", prim="kdf", fn="keyderive")
rule("Crypto.Protocol.KDF.scrypt", alg="scrypt", prim="kdf", fn="keyderive")

# --------------------------------------------------------------------------
# rsa (pure-Python RSA library)
# --------------------------------------------------------------------------
rule("rsa.newkeys", alg="RSA", prim="pke", fn="keygen", size=(0, "nbits"))
rule("rsa.encrypt", alg="RSA", prim="pke", fn="encrypt")
rule("rsa.sign", alg="RSA", prim="signature", fn="sign", hash_arg=(2, "hash_method"))

# --------------------------------------------------------------------------
# PyJWT and python-jose: the algorithm is a string such as "RS256"
# --------------------------------------------------------------------------
rule(["jwt.encode", "jose.jwt.encode", "jwt.api_jwt.encode"], handler="jwt_encode")
rule(["jwt.decode", "jose.jwt.decode", "jwt.api_jwt.decode"], handler="jwt_decode")

# --------------------------------------------------------------------------
# paramiko (SSH keys)
# --------------------------------------------------------------------------
rule(["paramiko.SSHClient", "paramiko.client.SSHClient", "paramiko.Transport",
      "paramiko.transport.Transport"], alg="SSH", prim="protocol", fn="connect",
     note="paramiko only offers classical SSH key exchange (curve25519, ECDH, DH)")
rule("paramiko.RSAKey.generate", alg="RSA", prim="signature", fn="keygen", size=(0, "bits"))
rule(["paramiko.RSAKey", "paramiko.RSAKey.from_private_key_file",
      "paramiko.RSAKey.from_private_key"], alg="RSA", prim="signature", fn="keyload")
rule("paramiko.DSSKey.generate", alg="DSA", prim="signature", fn="keygen", size=(0, "bits"))
rule(["paramiko.DSSKey", "paramiko.DSSKey.from_private_key_file"],
     alg="DSA", prim="signature", fn="keyload")
rule("paramiko.ECDSAKey.generate", handler="paramiko_ecdsa")
# the same key classes imported from their own modules
for mod, cls in [("rsakey", "RSAKey"), ("dsskey", "DSSKey"), ("ecdsakey", "ECDSAKey"),
                 ("ed25519key", "Ed25519Key")]:
    for suffix in ("", ".generate", ".from_private_key_file", ".from_private_key"):
        short = f"paramiko.{cls}{suffix}"
        if short in RULES:
            RULES[f"paramiko.{mod}.{cls}{suffix}"] = RULES[short]
rule(["paramiko.ECDSAKey", "paramiko.ECDSAKey.from_private_key_file"],
     alg="ECDSA", prim="signature", fn="keyload")
rule(["paramiko.Ed25519Key", "paramiko.Ed25519Key.from_private_key_file"],
     alg="Ed25519", prim="signature", fn="keyload")

# --------------------------------------------------------------------------
# ssl (Python standard library)
# --------------------------------------------------------------------------
rule("ssl.SSLContext", handler="ssl_context", arg=(0, "protocol"))
rule(["ssl.create_default_context", "ssl.wrap_socket", "ssl._create_unverified_context"],
     alg="TLS", prim="protocol", fn="connect",
     note="Negotiated TLS version and key exchange decide quantum safety; run the TLS checker on the server")

# --------------------------------------------------------------------------
# Other common libraries
# --------------------------------------------------------------------------
rule("nacl.public.PrivateKey.generate", alg="X25519", prim="key-agree", fn="keygen")
rule("nacl.signing.SigningKey.generate", alg="Ed25519", prim="signature", fn="keygen")
rule("nacl.secret.SecretBox", alg="XSalsa20-Poly1305", prim="ae", fn="encrypt")
rule("ecdsa.SigningKey.generate", alg="ECDSA", prim="signature", fn="keygen", curve=(None, "curve"))
rule("bcrypt.hashpw", alg="bcrypt", prim="kdf", fn="keyderive")
# liboqs-python: post-quantum algorithms (green)
rule("oqs.KeyEncapsulation", handler="pqc_by_name", prim="kem", arg=(0, "alg_name"))
rule("oqs.Signature", handler="pqc_by_name", prim="signature", arg=(0, "alg_name"))


# --------------------------------------------------------------------------
# Name tables used by the handlers
# --------------------------------------------------------------------------
HASH_NAMES = {
    "md2": "MD2", "md4": "MD4", "md5": "MD5", "sha1": "SHA-1", "sha": "SHA-1",
    "sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384",
    "sha512": "SHA-512", "sha512224": "SHA-512/224", "sha512256": "SHA-512/256",
    "sha3224": "SHA3-224", "sha3256": "SHA3-256", "sha3384": "SHA3-384",
    "sha3512": "SHA3-512", "blake2b": "BLAKE2b", "blake2s": "BLAKE2s",
    "shake128": "SHAKE128", "shake256": "SHAKE256", "ripemd160": "RIPEMD-160",
    "sm3": "SM3",
}

JWT_ALGS = {
    "HS256": ("HMAC-SHA-256", None, "mac"), "HS384": ("HMAC-SHA-384", None, "mac"),
    "HS512": ("HMAC-SHA-512", None, "mac"),
    "RS256": ("RSA", None, "signature"), "RS384": ("RSA", None, "signature"),
    "RS512": ("RSA", None, "signature"), "PS256": ("RSA", None, "signature"),
    "PS384": ("RSA", None, "signature"), "PS512": ("RSA", None, "signature"),
    "ES256": ("ECDSA", "P-256", "signature"), "ES384": ("ECDSA", "P-384", "signature"),
    "ES512": ("ECDSA", "P-521", "signature"), "ES256K": ("ECDSA", "secp256k1", "signature"),
    "EdDSA": ("EdDSA", None, "signature"), "none": ("NULL", None, "signature"),
}

CURVES = {
    "secp256r1": "P-256", "prime256v1": "P-256", "p256": "P-256", "nistp256": "P-256",
    "nist256p": "P-256", "secp384r1": "P-384", "p384": "P-384", "nistp384": "P-384",
    "nist384p": "P-384", "secp521r1": "P-521", "p521": "P-521", "nistp521": "P-521",
    "nist521p": "P-521", "secp256k1": "secp256k1", "secp224r1": "P-224",
    "p224": "P-224", "nist224p": "P-224", "secp192r1": "P-192", "nist192p": "P-192",
    "ed25519": "Ed25519", "curve25519": "Curve25519", "brainpoolp256r1": "brainpoolP256r1",
    "brainpoolp384r1": "brainpoolP384r1", "brainpoolp512r1": "brainpoolP512r1",
}

SSL_PROTOCOLS = {
    "PROTOCOL_SSLv2": "SSLv2", "PROTOCOL_SSLv3": "SSLv3",
    "PROTOCOL_TLSv1": "TLS 1.0", "PROTOCOL_TLSv1_1": "TLS 1.1",
    "PROTOCOL_TLSv1_2": "TLS 1.2",
}

# Functions that return N random bytes: used to work out AES key sizes.
RANDOM_BYTES = {"os.urandom", "secrets.token_bytes", "Crypto.Random.get_random_bytes",
                "random.randbytes"}

# Results table 1: known-answer test files

| Test file | Expected | Correct | Missed | Partial | False alarms | Result |
|---|---|---|---|---|---|---|
| tc01_md5 | MD5@7 | 1 | 0 | 0 | 0 | PASS |
| tc02_sha256 | SHA-256@6 | 1 | 0 | 0 | 0 | PASS |
| tc03_import_styles | SHA-1@6, SHA-512@7, SHA-256@8 | 3 | 0 | 0 | 0 | PASS |
| tc04_hmac_sha1 | HMAC-SHA-1@7, HMAC-SHA-1@11 | 2 | 0 | 0 | 0 | PASS |
| tc05_aes256_gcm | AES-256@7 | 1 | 0 | 0 | 0 | PASS |
| tc06_aes128_cbc | AES-128@8 | 1 | 0 | 0 | 0 | PASS |
| tc07_rsa2048_keygen | RSA-2048@5 | 1 | 0 | 0 | 0 | PASS |
| tc08_rsa_sign_pss | RSA-3072@5, RSA@8, SHA-256@8, SHA-256@10 | 4 | 0 | 0 | 0 | PASS |
| tc09_ecdsa_p384 | EC-P-384@5, ECDSA@6, SHA-384@6 | 3 | 0 | 0 | 0 | PASS |
| tc10_ed25519_x25519 | Ed25519@5, X25519@6, X25519@7 | 3 | 0 | 0 | 0 | PASS |
| tc11_dh_dsa | DH-2048@4, DSA-1024@5 | 2 | 0 | 0 | 0 | PASS |
| tc12_pycryptodome_aes | AES-256@6 | 1 | 0 | 0 | 0 | PASS |
| tc13_pycryptodome_rsa | RSA-2048@5, RSA@6 | 2 | 0 | 0 | 0 | PASS |
| tc14_pycryptodome_legacy | 3DES@7, MD5@8 | 2 | 0 | 0 | 0 | PASS |
| tc15_rsa_library | RSA-2048@4, RSA@5, SHA-256@5 | 3 | 0 | 0 | 0 | PASS |
| tc16_jwt | HMAC-SHA-256@5, HMAC-SHA-256@6, ECDSA-P-256@10, RSA@14 | 4 | 0 | 0 | 0 | PASS |
| tc17_paramiko | RSA-2048@4, ECDSA-P-256@5, Ed25519@6 | 3 | 0 | 0 | 0 | PASS |
| tc18_ssl_contexts | TLS 1.0@5, TLS@6 | 2 | 0 | 0 | 0 | PASS |
| tc19_fernet_pbkdf2 | PBKDF2-SHA-256@10, AES-128@12 | 2 | 0 | 0 | 0 | PASS |
| tc20_pqc_oqs | ML-KEM-768@4, ML-DSA-65@5 | 2 | 0 | 0 | 0 | PASS |
| tc21_tricky_variable | SHA-1@8, MD5@15 | 2 | 0 | 0 | 0 | PASS |
| tc22_tricky_runtime_name | SHA-1@11, RSA@15 | 0 | 2 | 2 | 0 | FAIL |
| tc23_tricky_getattr | MD5@7, SHA-1@11 | 0 | 2 | 0 | 0 | FAIL |
| tc24_tricky_config | MD5@12, SHA-1@20, RSA-2048@23 | 0 | 3 | 2 | 0 | FAIL |
| tc25_tricky_no_crypto | (nothing) | 0 | 0 | 0 | 1 | FAIL |
| tc26_rsa3072_cert | RSA@1, RSA-3072@1 | 2 | 0 | 0 | 0 | PASS |
| tc27_ec_p256_key | EC-P-256@1 | 1 | 0 | 0 | 0 | PASS |
| tc28_ed25519_cert | Ed25519@1 | 1 | 0 | 0 | 0 | PASS |
| tc29_requirements | cryptography@3, pycryptodome@4, pyjwt@6 | 3 | 0 | 0 | 0 | PASS |
| tc30_pyproject | paramiko@6, rsa@7, python-jose@11 | 3 | 0 | 0 | 0 | PASS |

| Group | Files | Expected items | Correct | Missed | False alarms | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| Standard cases | 25 | 53 | 53 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| Tricky cases | 5 | 9 | 2 | 7 | 1 | 66.7% | 22.2% | 33.3% |
| All 30 files | 30 | 62 | 55 | 7 | 1 | 98.2% | 88.7% | 93.2% |

## What the tool got wrong

- **tc22_tricky_runtime_name** missed: SHA-1@11; RSA@15
- **tc23_tricky_getattr** missed: MD5@7; SHA-1@11
- **tc24_tricky_config** missed: MD5@12; SHA-1@20; RSA-2048@23
- **tc25_tricky_no_crypto** false alarm: SHA-1@27

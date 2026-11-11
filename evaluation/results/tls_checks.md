# Results table 3: TLS checks (our checker vs. sslyze)

| Target | Check | Our TLS checker | sslyze | Agree |
|---|---|---|---|---|
| localhost:8444 | TLS versions accepted | TLS 1.2 | TLS 1.2 | yes |
| localhost:8444 | Certificate key | RSA-2048 | RSA-2048 | yes |
| localhost:8444 | Certificate signature | RSA (SHA-256) | RSA (SHA-256) | yes |
| localhost:8444 | Key exchange group | X25519 | supported: X25519, X448, secp256r1, secp384r1, secp521r1 | yes |
| example.com | TLS versions accepted | TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3 | TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3 | yes |
| example.com | Certificate key | EC-P-256 | EC-P-256 | yes |
| example.com | Certificate signature | ECDSA (SHA-256) | ECDSA (SHA-256) | yes |
| example.com | Key exchange group | X25519 | supported: X25519, secp256r1, secp384r1, secp521r1 | yes |
| wikipedia.org | TLS versions accepted | TLS 1.2, TLS 1.3 | TLS 1.2, TLS 1.3 | yes |
| wikipedia.org | Certificate key | EC-P-256 | EC-P-256 | yes |
| wikipedia.org | Certificate signature | ECDSA (SHA-384) | ECDSA (SHA-384) | yes |
| wikipedia.org | Key exchange group | X25519 | supported: X25519, secp256r1 | yes |

"""SSH keys with paramiko."""
import paramiko

rsa_key = paramiko.RSAKey.generate(bits=2048)  # expect: RSA-2048
ec_key = paramiko.ECDSAKey.generate()  # expect: ECDSA-P-256
host_key = paramiko.Ed25519Key(filename="/etc/ssh/ssh_host_ed25519_key")  # expect: Ed25519

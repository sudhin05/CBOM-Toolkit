"""Post-quantum key encapsulation and signatures with liboqs-python."""
import oqs

kem = oqs.KeyEncapsulation("ML-KEM-768")  # expect: ML-KEM-768
signer = oqs.Signature("ML-DSA-65")  # expect: ML-DSA-65
public_key = kem.generate_keypair()

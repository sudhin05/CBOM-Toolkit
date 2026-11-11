"""RSA-OAEP encryption with pycryptodome."""
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

key = RSA.generate(2048)  # expect: RSA-2048
cipher = PKCS1_OAEP.new(key.publickey())  # expect: RSA
ciphertext = cipher.encrypt(b"secret")

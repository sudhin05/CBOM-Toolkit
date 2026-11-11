"""AES-128 in CBC mode."""
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = os.urandom(16)
iv = os.urandom(16)
encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()  # expect: AES-128

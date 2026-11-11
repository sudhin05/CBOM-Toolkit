"""Legacy 3DES encryption and MD5 hash with pycryptodome."""
from Crypto.Cipher import DES3
from Crypto.Hash import MD5
from Crypto.Random import get_random_bytes

key = DES3.adjust_key_parity(get_random_bytes(24))
cipher = DES3.new(key, DES3.MODE_CBC)  # expect: 3DES
digest = MD5.new(b"data").hexdigest()  # expect: MD5

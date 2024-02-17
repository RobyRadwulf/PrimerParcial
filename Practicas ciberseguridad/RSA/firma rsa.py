import Crypto.Util.number
import Crypto.Random
import hashlib
from rsa import nA, dA, e

# Message to be signed
msg = "Hola Mundo"

# Hash the message using a secure hash function (SHA-256)
hash_msg = hashlib.sha256(msg.encode()).digest()

# Sign the hash
signature = pow(int.from_bytes(hash_msg, 'big'), dA, nA)

# Verify the signature
hash_signature = pow(signature, e, nA)

if int.to_bytes(hash_signature, 32, 'big') == hash_msg:
    print("La firma es válida. El mensaje ha sido firmado por Alice.")
else:
    print("La firma no es válida. El mensaje no ha sido firmado por Alice o ha sido alterado.")
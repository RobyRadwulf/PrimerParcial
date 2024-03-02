import Crypto.Util.number
import hashlib

M = "Primer_Parcial" * 75
MessageBytes = bytes(M, 'utf-8')
MessageHash = hashlib.sha256(MessageBytes).hexdigest()
Message = [M[i:i+128] for i in range(0, len(M), 128)]
bits= 1024

#Obtener los primos para Alice y Bob
qA=Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qB=Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
pA=Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
pB=Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)

#Obtenemos la primera parte de la llave publica de Alice y Bob
nA=qA*qB
nB=pA*pB

#Calculamos la funcion de Euler Phi
phiA=(qA-1)*(qB-1)
phiB=(pA-1)*(pB-1)

e=65537

#calcular la llave privada de Alice y Bob
dA=Crypto.Util.number.inverse(e, phiA)
dB=Crypto.Util.number.inverse(e, phiB)

MessageCoded = []

#Ciframos el mensaje
for j in Message:
    w = int.from_bytes(str(j).encode('utf-8'), byteorder='big')
    c = pow(w, e, nB)
    print("Mensaje cifrado: ", c, "\n")
    MessageCoded.append(c)

decrypted_msgs = []
#Desciframos el mensaje
for c in MessageCoded:
    w = pow(c, dB, nB)
    decrypted_msg_bytes = w.to_bytes((w.bit_length() + 7) // 8, byteorder='big')
    decrypted_msgs.append(decrypted_msg_bytes)
    #unimos el mensaje
joined_msg = b''.join(decrypted_msgs).decode('utf-8')

print("Mensaje Original: ", M)
print("Mensaje Hash: ",MessageHash)
print("Mensaje Dividido: ", Message, "\n")

print("pA: ", pA)
print("qA: ", qA)
print("pB: ", pB)
print("qB: ", qB ,"\n")

print("nA: ", nA)
print("nB: ", nB ,"\n")

print("phiA: ", phiA)
print("phiB: ", phiB ,"\n")

print("dA: ", dA)
print("dB: ", dB ,"\n")

print("Mensaje: ", joined_msg)

MessageJoined = "¿El mensaje es igual?:"
if M == joined_msg:
    print(MessageJoined, True)
else:
    print(MessageJoined, False)


import Crypto.Util.number
import Crypto.Random


#Numero de bits
bits = 1024

#Obtener los primos para Alice y Bob
pA = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
print("pA: ", pA ,"\n")
qA = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
print("qA: ", qA ,"\n")
pB = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
print("pB: ", pB ,"\n")
qB = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
print("qB: ", qB ,"\n")

#Obtenemos la primera parte de la llave publica de Alice y Bob
nA = pA * qA
print("nA: ", nA ,"\n")
nB = pB * qB
print("nB: ", nB ,"\n")

#Calculamos la funcion de Euler Phi
phiA = (pA - 1) * (qA - 1)
print("phiA: ", phiA ,"\n")

phiB = (pB - 1) * (qB - 1)
print("phiB: ", phiB ,"\n")

e= 65537

#calcular la llave privada de Alice y Bob
dA = Crypto.Util.number.inverse(e, phiA)
print("dA: ", dA ,"\n")

dB = Crypto.Util.number.inverse(e, phiB)
print("dB: ", dB ,"\n")

#Ciframos el mensaje
msg = "Hola Mundo"
print("Mensaje: ", msg ,"\n")
print("Mensaje en bytes: ", len(msg.encode('utf-8')))

#Convertimos el mensaje a bytes
m = int.from_bytes(msg.encode('utf-8'), byteorder='big')
print("Mensaje en bytes: ", m ,"\n")

c= pow(m, e, nB)

#Desciframos el mensaje
des = pow(c, dB, nB)
msg_final = int.to_bytes(des, len(msg), byteorder='big').decode('utf-8')
print("Mensaje descifrado: ", msg_final ,"\n")

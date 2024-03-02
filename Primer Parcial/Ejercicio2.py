import io
import os
import Crypto.Util.number
import Crypto.Random
import hashlib
import PyPDF2
from PyPDF2 import PdfReader
def sign_document(document, private_key):
    hash_document = hashlib.sha256(document).digest()
    signature = pow(int.from_bytes(hash_document, byteorder='big'), private_key[0], private_key[1])
    return signature
def verify_signature(document, signature, public_key):
    hash_document = hashlib.sha256(document).digest()
    hash_signature = pow(signature, public_key[0], public_key[1])
    return hash_document == hash_signature.to_bytes((hash_signature.bit_length() + 7) // 8, byteorder='big')

bits = 1024

#Obtener los primos para Alice, Bob y la Autoridad Certificadora (AC)
pA = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qA = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
pB = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qB = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
pAC = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qAC = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)

#Obtenemos la primera parte de la llave publica de Alice, Bob y la Autoridad Certificadora (AC)
nA = pA * qA
nB = pB * qB
nAC = pAC * qAC

#Calculamos la funcion de Euler Phi
phiA = (pA - 1) * (qA - 1)
phiB = (pB - 1) * (qB - 1)
phiAC = (pAC - 1) * (qAC - 1)

e = 65537

#calcular la llave privada de Alice, Bob y la Autoridad Certificadora (AC)
dA = Crypto.Util.number.inverse(e, phiA)
dB = Crypto.Util.number.inverse(e, phiB)
dAC = Crypto.Util.number.inverse(e, phiAC)

#cargamos el PDF
with open('NDA.pdf', 'rb') as file:
    document = file.read()

#ALice firma el documento
alice_signature = sign_document(document, (dA, nA))

#Alice modifica el PDF
with open('Alice_signed_NDA.pdf', 'wb') as file:
    writer = PyPDF2.PdfWriter()
    reader = PyPDF2.PdfReader(io.BytesIO(document))
    for page_num in range(len(reader.pages)):
        writer.add_page(reader.pages[page_num])
    writer.add_metadata({'/Firma_Alice': str(alice_signature)})
    writer.write(file)

#AC obtiene el PDF y lo comprueba con la llave publica de Alice
alice_public_key = (e, nA)
is_valid_signature = verify_signature(document, alice_signature, alice_public_key)
ACver = "AC verificó la firma de Alice?:"
if is_valid_signature:
    print(ACver, True)
else:
    print(ACver, False)

#AC firma el PDF y lo añade y se lo manda a Bob
ac_signature = sign_document(document, (dAC, nAC))
with open('AC_signed_NDA.pdf', 'wb') as file:
    writer = PyPDF2.PdfWriter()
    reader = PyPDF2.PdfReader(io.BytesIO(document))
    for page_num in range(len(reader.pages)):
        writer.add_page(reader.pages[page_num])
    writer.add_metadata({'/Firma_AC': str(ac_signature)})  # Adding AC's signature as metadata
    writer.write(file)

#Bob obtiene el PDF y lo comprueba con la llave publica de AC
ac_public_key = (e, nAC)
is_valid_signature = verify_signature(document, ac_signature, ac_public_key)
Bver = "Bob verificó la firma de AC?:"
if is_valid_signature:
    print(Bver, True)
else:
    print(Bver, False, "\n")

#Comprobar los datos en las Firmas en los PDF´s
def print_pdf_metadata(pdf_path):
    print(f"Inspecting {pdf_path}")
    print("File Name:", os.path.basename(pdf_path), end='')
    with open(pdf_path, 'rb') as file:
        reader = PdfReader(file)
        metadata = reader.metadata
        if metadata:
            print("\nMetadata:")
            for key, value in metadata.items():
                print(f"{key}: {value}")
        else:
            print("No metadata found.")
    print()
def inspect_all_pdfs(directory):
    for filename in os.listdir(directory):
        if filename.endswith('.pdf'):
            pdf_path = os.path.join(directory, filename)
            print_pdf_metadata(pdf_path)

#cambiar path dependiendo de la ubi de los PDF´s
directory = r'C:\Users\robyr\OneDrive\Escritorio\Anahuac\8vo_semestre\Primer Parcial'
inspect_all_pdfs(directory)

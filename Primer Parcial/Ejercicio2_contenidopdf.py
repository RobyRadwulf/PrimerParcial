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
def add_signature_to_pdf(pdf_path, signature):
    with open(pdf_path, 'rb') as file:
        reader = PyPDF2.PdfReader(file)
        num_pages = len(reader.pages)
        writer = PyPDF2.PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        for page_num in range(num_pages):
            page = reader.pages[page_num]
            content_object = page['/Contents']
            content = content_object.get_object()
            content_stream = content.get_data()

            watermark_stream = f"BT /F1 24 Tf 50 750 Td ({signature}) Tj ET".encode()
            content_stream = watermark_stream + b"\n" + content_stream

            content.set_data(content_stream)
            page.__setitem__('/Contents', content)
            writer.add_page(page)

        output_path = f"modified_{os.path.basename(pdf_path)}"
        with open(output_path, 'wb') as output_file:
            writer.write(output_file)
        return output_path

def print_pdf_metadata(pdf_path):
    print(f"Inspecting {pdf_path}")
    print("File Name:", os.path.basename(pdf_path))
    with open(pdf_path, 'rb') as file:
        reader = PyPDF2.PdfReader(file)
        metadata = reader.metadata
        if metadata:
            print("\nMetadata:")
            for key, value in metadata.items():
                print(f"{key}: {value}")
        else:
            print("No metadata found.")
    print()

bits = 1024

# Obtener los primos para Alice, Bob y la Autoridad Certificadora (AC)
pA = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qA = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
pB = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qB = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
pAC = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qAC = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)

# Obtenemos la primera parte de la llave publica de Alice, Bob y la Autoridad Certificadora (AC)
nA = pA * qA
nB = pB * qB
nAC = pAC * qAC

# Calculamos la funcion de Euler Phi
phiA = (pA - 1) * (qA - 1)
phiB = (pB - 1) * (qB - 1)
phiAC = (pAC - 1) * (qAC - 1)

e = 65537

# calcular la llave privada de Alice, Bob y la Autoridad Certificadora (AC)
dA = Crypto.Util.number.inverse(e, phiA)
dB = Crypto.Util.number.inverse(e, phiB)
dAC = Crypto.Util.number.inverse(e, phiAC)

private_key = (dA, nA)
public_key = (e, nA)
def inspect_all_pdfs(directory):
    for filename in os.listdir(directory):
        if filename.endswith('.pdf'):
            pdf_path = os.path.join(directory, filename)
            print_pdf_metadata(pdf_path)

            # Load the PDF content
            with open(pdf_path, 'rb') as file:
                document = file.read()

            # AC firma el documento
            ac_signature = sign_document(document, (dAC, nAC))

            # AC modifica el PDF con su firma
            with open(f'AC_signed_{filename}', 'wb') as ac_file:
                writer = PyPDF2.PdfWriter()
                reader = PyPDF2.PdfReader(io.BytesIO(document))
                for page_num in range(len(reader.pages)):
                    writer.add_page(reader.pages[page_num])
                writer.add_metadata({'/Firma_AC': str(ac_signature)})  # Adding AC's signature as metadata
                writer.write(ac_file)
                print("AC signature added to:", f'AC_signed_{filename}')

            # Alice firma el documento
            alice_signature = sign_document(document, private_key)

            # Alice modifica el PDF con su firma
            with open(f'Alice_signed_{filename}', 'wb') as alice_file:
                writer = PyPDF2.PdfWriter()
                reader = PyPDF2.PdfReader(io.BytesIO(document))
                for page_num in range(len(reader.pages)):
                    writer.add_page(reader.pages[page_num])
                writer.add_metadata({'/Firma_Alice': str(alice_signature)})  # <--- Changed to 'Alice' for clarity
                writer.write(alice_file)
                print("Alice signature added to:", f'Alice_signed_{filename}')

            alice_public_key = (public_key[0], public_key[1])
            is_valid_signature = verify_signature(document, alice_signature, alice_public_key)
            ACver = "¿AC verificó la firma de Alice?:"
            if is_valid_signature:
                print(ACver, True)
            else:
                print(ACver, False)

            ac_public_key = (e, nAC)
            is_valid_signature = verify_signature(document, ac_signature, ac_public_key)
            Bver = "¿Bob verificó la firma de AC?:"
            if is_valid_signature:
                print(Bver, True)
            else:
                print(Bver, False, "\n")

directory = r'C:\Users\robyr\OneDrive\Escritorio\Anahuac\8vo_semestre\Primer Parcial'
inspect_all_pdfs(directory)



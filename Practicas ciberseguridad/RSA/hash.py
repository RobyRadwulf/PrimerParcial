import hashlib
def calcular_hash_archivo(pdf):
    with open(pdf, "rb") as f:
        contenido = f.read()
        hash_resultado = hashlib.sha256(contenido).hexdigest()
    return hash_resultado

# Hash de una cadena de texto de 8 bits
c_8bits = "12345678"
hash_cadena_8bits = hashlib.sha256(c_8bits.encode()).hexdigest()
print("Hash de cadena de 8 bits:".ljust(30), hash_cadena_8bits)

# Hash de una cadena de texto de 1024 bits
c_1024bits = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
hash_cadena_1024bits = hashlib.sha256(c_1024bits.encode()).hexdigest()
print("Hash de cadena de 1024 bits:".ljust(30), hash_cadena_1024bits)

# Hash de un archivo PDF
pdf = r"C:\Users\robyr\OneDrive\Escritorio\Anahuac\8vo_semestre\Practicas ciberseguridad\RSA\hash.pdf"
hash_pdf = calcular_hash_archivo(pdf)
print("Hash del archivo PDF:".ljust(30), hash_pdf)

print("hash pdf pasado:".ljust(30), "c19bccba401753f20509688bb3e586c26c11523f2e4eb40dd314c666e82f54d5")


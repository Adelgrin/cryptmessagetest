import os
from cryptography.hazmat.primitives import serialization

# Função para carregar a chave privada de um arquivo
def load_private_key(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
        )

# Função para salvar a chave pública em um arquivo
def save_public_key(key, filename):
    with open(filename, "wb") as f:
        f.write(key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet


# --------- RSA ---------
def gerar_par_de_chaves_rsa():
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    chave_publica = chave_privada.public_key()
    return chave_privada, chave_publica


def chave_publica_pem(chave_publica):
    return chave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def chave_privada_pem(chave_privada):
    return chave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def carregar_chave_publica(pem):
    return serialization.load_pem_public_key(pem)


def carregar_chave_privada(pem):
    return serialization.load_pem_private_key(pem, password=None)


def criptografar_rsa(mensagem, chave_publica):
    return chave_publica.encrypt(
        mensagem,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def descriptografar_rsa(mensagem_cripto, chave_privada):
    return chave_privada.decrypt(
        mensagem_cripto,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# --------- AES (Fernet) ---------
def gerar_chave_aes():
    return Fernet.generate_key()


def criptografar_aes(mensagem, chave_aes):
    f = Fernet(chave_aes)
    return f.encrypt(mensagem.encode())


def descriptografar_aes(mensagem_cripto, chave_aes):
    f = Fernet(chave_aes)
    return f.decrypt(mensagem_cripto).decode()

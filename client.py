import socket
import base64
#from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding 
from cryptography.hazmat.primitives import hashes, serialization
# Configurações do servidor (coloque o IP do servidor)
HOST = '127.0.0.1'  # Exemplo: '192.168.1.10'
PORT = 5000

#NOTE: Cria o socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#NOTE: Conecta ao servidor
client_socket.connect((HOST, PORT))
print(f"Conectado ao servidor em {HOST}:{PORT}")

#NOTE: Gera par de chaves
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()


def encrypt_message(message, public_key):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

def decrypt_message(token, private_key):
    ciphertext = base64.b64decode(token)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

#NOTE: antigamente salvava as chaves em arquivo para ultilizacao recorrente

# Função para salvar chave em arquivo
#def save_key(key, filename):
#    with open(filename, "wb") as f:
#        f.write(key)

# Função para carregar chave de arquivo
#def load_key(filename):
#    with open(filename, "rb") as f:
#        return f.read()

#save_key(private_key, "aes_private.key")
#save_key(public_key, "aes_public.key")

# Serializar a chave pública para bytes (formato PEM)
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

client_socket.sendall(public_key_bytes)
public_other_key = client_socket.recv(1024)

# Adicione esta linha para garantir que a chave está correta:
public_other_key = serialization.load_pem_public_key(public_other_key)

try:
    while True:
        mensagem = input("Digite sua mensagem: ")
        # Envia mensagem criptografada como base64 string codificada em bytes
        client_socket.sendall(encrypt_message(mensagem, public_other_key).encode())

        dados = client_socket.recv(1024)
        # Recebe resposta como bytes, decodifica para string base64, depois descriptografa
        resposta = decrypt_message(dados.decode(), private_key)
        print(f"Resposta do servidor: {resposta}")

except Exception as e:
    print(f"Ocorreu um erro: {e}")
finally:
    client_socket.close()

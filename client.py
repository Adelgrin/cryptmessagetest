import socket
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Configurações do servidor (coloque o IP do servidor)
HOST = '127.0.0.1'  # Exemplo: '192.168.1.10'
PORT = 5000

# Cria o socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Conecta ao servidor
client_socket.connect((HOST, PORT))
print(f"Conectado ao servidor em {HOST}:{PORT}")

def encrypt_message(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ct).decode()

def decrypt_message(token, key):
    data = base64.b64decode(token)
    iv = data[:16]
    ct = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(ct) + decryptor.finalize()).decode()

def generate_aes_key():
    return os.urandom(32)  # 256 bits

# Função para salvar chave em arquivo
def save_key(key, filename):
    with open(filename, "wb") as f:
        f.write(key)

# Função para carregar chave de arquivo
def load_key(filename):
    with open(filename, "rb") as f:
        return f.read()

# Geração e salvamento das chaves
private_key = generate_aes_key()
public_key = generate_aes_key()  # AES não tem chave pública, mas para fins de demonstração

save_key(private_key, "aes_private.key")
save_key(public_key, "aes_public.key")

client_socket.sendall(public_key)
public_other_key = client_socket.recv(1024)

try:
    while True:
        mensagem = input("Digite sua mensagem: ")
        client_socket.sendall(encrypt_message(mensagem,public_other_key).encode())

        dados = client_socket.recv(1024)
        print(f"Resposta do servidor: {decrypt_message(dados.decode(),private_key)}")

except Exception as e:
    print(f"Ocorreu um erro: {e}")
finally:
    client_socket.close()

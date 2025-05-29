import socket
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Configurações do servidor
HOST = '127.0.0.1'  # Aceita conexões de qualquer IP
PORT = 5000       # Porta para escutar

# Cria o socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Associa o socket ao host e porta
server_socket.bind((HOST, PORT))

# Começa a escutar (máximo 1 conexão na fila)
server_socket.listen(1)
print(f"Servidor escutando em {HOST}:{PORT}")

# Aceita uma conexão
conn, addr = server_socket.accept()
print(f"Conectado por {addr}")

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

conn.sendall(public_key)
public_other_key = conn.recv(1024)

try:
    while True:
        data = conn.recv(1024)  # Recebe até 1024 bytes
        if not data:
            break
        print(f"Mensagem recebida: {decrypt_message(data.decode(), private_key)}")
        
        resposta = input("Digite sua resposta: ")
        conn.sendall(encrypt_message(resposta, public_other_key).encode())

except Exception as e:
    print(f"Ocorreu um erro: {e}")
finally:
    conn.close()
    server_socket.close()

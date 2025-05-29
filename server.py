import socket
import base64
#from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding 
from cryptography.hazmat.primitives import hashes, serialization

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

# Gerar par de chaves RSA
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

# Envie public_key_bytes pelo socket
conn.sendall(public_key_bytes)
public_other_key = conn.recv(1024)

# Adicione esta linha para garantir que a chave está correta:
public_other_key = serialization.load_pem_public_key(public_other_key)

try:
    while True:
        data = conn.recv(1024)  # Recebe até 1024 bytes
        if not data:
            break
        # Corrigido: só decodifique se for mensagem (base64)
        mensagem = decrypt_message(data.decode(), private_key)
        #print(f"Mensagem criptografada: {data.decode()}")
        print(f"Mensagem recebida: {mensagem}")
        
        resposta = input("Digite sua resposta: ")
        conn.sendall(encrypt_message(resposta, public_other_key).encode())

except Exception as e:
    print(f"Ocorreu um erro: {e}")
finally:
    conn.close()
    server_socket.close()

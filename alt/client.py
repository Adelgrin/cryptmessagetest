import socket
from crypto_utils import (
    carregar_chave_publica,
    criptografar_rsa,
    gerar_chave_aes,
    criptografar_aes,
    descriptografar_aes
)

# Configurações
HOST = '127.0.0.1'  # Ex.: '192.168.1.10'
PORT = 5000

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))
print(f"Conectado ao servidor em {HOST}:{PORT}")

# Recebe chave pública do servidor
chave_publica_pem = b""
while True:
    parte = client_socket.recv(2048)
    chave_publica_pem += parte
    if b"-----END PUBLIC KEY-----" in chave_publica_pem:
        break

chave_publica = carregar_chave_publica(chave_publica_pem)
print("Chave pública recebida.")

# Gera chave AES
chave_aes = gerar_chave_aes()

# Envia chave AES criptografada com RSA
aes_cripto = criptografar_rsa(chave_aes, chave_publica)
client_socket.sendall(aes_cripto)
print("Chave AES enviada.")

try:
    while True:
        mensagem = input("Digite sua mensagem: ")
        mensagem_cripto = criptografar_aes(mensagem, chave_aes)
        client_socket.sendall(mensagem_cripto)

        dados = client_socket.recv(4096)
        resposta = descriptografar_aes(dados, chave_aes)
        print(f"Resposta do servidor: {resposta}")

except Exception as e:
    print(f"Ocorreu um erro: {e}")
finally:
    client_socket.close()

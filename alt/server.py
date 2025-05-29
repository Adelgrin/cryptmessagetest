import socket
from crypto_utils import (
    gerar_par_de_chaves_rsa,
    chave_publica_pem,
    chave_privada_pem,
    carregar_chave_privada,
    descriptografar_rsa,
    descriptografar_aes,
    criptografar_aes
)

# Gera chave RSA
chave_privada, chave_publica = gerar_par_de_chaves_rsa()
chave_privada_pem_bytes = chave_privada_pem(chave_privada)
chave_publica_pem_bytes = chave_publica_pem(chave_publica)

# Configurações
HOST = '127.0.0.1'
PORT = 5000

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)
print(f"Servidor escutando em {HOST}:{PORT}")

conn, addr = server_socket.accept()
print(f"Conectado por {addr}")

# Envia a chave pública para o cliente
conn.sendall(chave_publica_pem_bytes)
print("Chave pública enviada.")

# Recebe a chave AES criptografada com RSA
aes_cripto = conn.recv(512)
chave_aes = descriptografar_rsa(aes_cripto, chave_privada)
print("Chave AES recebida e descriptografada.")

try:
    while True:
        data = conn.recv(4096)
        if not data:
            break

        mensagem = descriptografar_aes(data, chave_aes)
        print(f"Mensagem recebida: {mensagem}")

        resposta = input("Digite sua resposta: ")
        resposta_cripto = criptografar_aes(resposta, chave_aes)
        conn.sendall(resposta_cripto)

except Exception as e:
    print(f"Ocorreu um erro: {e}")
finally:
    conn.close()
    server_socket.close()

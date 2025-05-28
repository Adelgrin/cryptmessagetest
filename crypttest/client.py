import socket

# Configurações do servidor (coloque o IP do servidor)
HOST = 'IP_DO_SERVIDOR'  # Exemplo: '192.168.1.10'
PORT = 5000

# Cria o socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Conecta ao servidor
client_socket.connect((HOST, PORT))
print(f"Conectado ao servidor em {HOST}:{PORT}")

try:
    while True:
        mensagem = input("Digite sua mensagem: ")
        client_socket.sendall(mensagem.encode())

        dados = client_socket.recv(1024)
        print(f"Resposta do servidor: {dados.decode()}")

except Exception as e:
    print(f"Ocorreu um erro: {e}")
finally:
    client_socket.close()

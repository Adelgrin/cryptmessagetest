import socket

# Configurações do servidor
HOST = '0.0.0.0'  # Aceita conexões de qualquer IP
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

try:
    while True:
        data = conn.recv(1024)  # Recebe até 1024 bytes
        if not data:
            break
        print(f"Mensagem recebida: {data.decode()}")
        
        resposta = input("Digite sua resposta: ")
        conn.sendall(resposta.encode())

except Exception as e:
    print(f"Ocorreu um erro: {e}")
finally:
    conn.close()
    server_socket.close()

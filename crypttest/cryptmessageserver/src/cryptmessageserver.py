import os
import socket
import threading
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.backends import default_backend
import base64

# Load the private key from a file
def load_private_key(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

# Decrypt the message using the private key
def decrypt_message(token, private_key):
    data = base64.b64decode(token)
    iv = data[:16]
    ct = data[16:]
    cipher = Cipher(algorithms.AES(private_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(ct) + decryptor.finalize()).decode()

# Function to handle client connections
def handle_client(client_socket, private_key):
    try:
        # Receive the public key from the client
        client_pub_key = client_socket.recv(1024)
        
        # Send the server's public key to the client
        with open("aes_public.key", "rb") as f:
            server_pub_key = f.read()
        client_socket.sendall(server_pub_key)

        while True:
            # Receive encrypted message from the client
            encrypted_message = client_socket.recv(4096)
            if not encrypted_message:
                break
            
            # Decrypt the message
            decrypted_message = decrypt_message(encrypted_message.decode(), private_key)
            print(f"Received: {decrypted_message}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

# Main function to start the server
def start_server():
    private_key = load_private_key("aes_private.key")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 12345))
    server.listen(5)
    print("Server listening on port 12345")

    while True:
        client_socket, addr = server.accept()
        print(f"Accepted connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, private_key))
        client_handler.start()

if __name__ == "__main__":
    start_server()
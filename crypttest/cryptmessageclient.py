import os
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import tkinter as tk
from tkinter import messagebox
import socket
from tkinter import simpledialog
from cryptography.hazmat.primitives.ciphers import Cipher, modes
import threading

# Função para gerar chave AES-256
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

# Interface gráfica simples
def show_keys():
    priv = base64.b64encode(load_key("aes_private.key")).decode()
    pub = base64.b64encode(load_key("aes_public.key")).decode()
    messagebox.showinfo("Chaves AES", f"Privada:\n{priv}\n\nPública:\n{pub}")

root = tk.Tk()
root.title("Janela de Mensagens Criptografadas")

btn = tk.Button(root, text="Mostrar Chaves AES", command=show_keys)
btn.pack(padx=20, pady=20)

def connect_to_server():
    server_ip = simpledialog.askstring("Conectar ao Servidor", "Digite o IP do servidor:")
    if not server_ip:
        messagebox.showerror("Erro", "IP do servidor não informado.")
        return
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_ip, 12345))  # Porta padrão 12345
            messagebox.showinfo("Conexão", f"Conectado ao servidor {server_ip}:12345")
    except Exception as e:
        messagebox.showerror("Erro de Conexão", f"Não foi possível conectar: {e}")

connect_btn = tk.Button(root, text="Conectar ao Servidor", command=connect_to_server)
connect_btn.pack(padx=20, pady=10)

# Adiciona área de texto para exibir mensagens
messages_text = tk.Text(root, height=15, width=50, state='disabled')
messages_text.pack(padx=20, pady=10)

# Adiciona campo de entrada para digitar mensagens
entry_message = tk.Entry(root, width=40)
entry_message.pack(side=tk.LEFT, padx=(20, 0), pady=10)

# Botão para enviar mensagem
send_btn = tk.Button(root, text="Enviar")
send_btn.pack(side=tk.LEFT, padx=10, pady=10)

# Variáveis globais para conexão e chave do outro cliente
client_socket = None
other_public_key = None


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

def connect_to_server():
    global client_socket, other_public_key
    server_ip = simpledialog.askstring("Conectar ao Servidor", "Digite o IP do servidor:")
    if not server_ip:
        messagebox.showerror("Erro", "IP do servidor não informado.")
        return
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_ip, 12345))
        messagebox.showinfo("Conexão", f"Conectado ao servidor {server_ip}:12345")
        # Troca de chaves: envia sua chave pública e recebe a do outro cliente
        with open("aes_public.key", "rb") as f:
            my_pub = f.read()
        client_socket.sendall(my_pub)
        other_public_key = client_socket.recv(1024)
        # Inicia thread para receber mensagens
        threading.Thread(target=receive_messages, daemon=True).start()
    except Exception as e:
        messagebox.showerror("Erro de Conexão", f"Não foi possível conectar: {e}")

def send_message():
    global client_socket, other_public_key
    msg = entry_message.get()
    if not msg or not client_socket or not other_public_key:
        return
    encrypted = encrypt_message(msg, other_public_key)
    try:
        client_socket.sendall(encrypted.encode())
        entry_message.delete(0, tk.END)
        append_message("Você: " + msg)
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao enviar mensagem: {e}")

def receive_messages():
    global client_socket, private_key
    while True:
        try:
            data = client_socket.recv(4096)
            if not data:
                break
            decrypted = decrypt_message(data.decode(), private_key)
            append_message("Outro: " + decrypted)
        except Exception:
            break

def append_message(msg):
    messages_text.config(state='normal')
    messages_text.insert(tk.END, msg + "\n")
    messages_text.config(state='disabled')
    messages_text.see(tk.END)

send_btn.config(command=send_message)
root.mainloop()
# Crypt Message Server

This project implements a TCP socket server that communicates with a client for sending and receiving encrypted messages. The server listens for incoming connections, receives encrypted messages from clients, decrypts them using a private key, and sends back the public key of the server.

## Project Structure

```
cryptmessageserver
├── src
│   ├── cryptmessageserver.py  # Implements the TCP socket server
│   └── utils.py               # Utility functions for key management
├── requirements.txt           # Project dependencies
└── README.md                  # Project documentation
```

## Setup Instructions

1. **Clone the repository**:
   ```
   git clone <repository-url>
   cd cryptmessageserver
   ```

2. **Install dependencies**:
   Make sure you have Python installed, then run:
   ```
   pip install -r requirements.txt
   ```

3. **Generate keys**:
   Before running the server, ensure that you have generated the necessary keys (private and public) and saved them in the appropriate files.

## Usage

1. **Run the server**:
   Execute the following command in your terminal:
   ```
   python src/cryptmessageserver.py
   ```

2. **Connect with the client**:
   Use the `cryptmessageclient.py` file to connect to the server. Enter the server's IP address when prompted.

## Example

- Start the server first, then run the client to establish a connection and start sending encrypted messages.

## Notes

- Ensure that the server and client are using compatible encryption methods and key sizes.
- The server is designed to handle multiple clients, but you may need to implement additional threading or asynchronous handling for scalability.
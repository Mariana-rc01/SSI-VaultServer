"""
Simple TLS Client.
Connects to the TLS server, sends a message, and prints the response.
Verifies the server's certificate using the CA's certificate.
"""

import socket, ssl

# CA certificate file (in PEM format)
CA_CERT_FILE = "ca_cert.pem"

def connect_to_server(server_host="localhost", server_port=8443):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT_FILE)
    with socket.create_connection((server_host, server_port)) as sock:
        with context.wrap_socket(sock, server_hostname=server_host) as ssock:
            print("Connected to the server using TLS.")
            message = "Hello, TLS Server!"
            ssock.sendall(message.encode())
            response = ssock.recv(1024)
            print("Server response:", response.decode())

if __name__ == "__main__":
    connect_to_server()

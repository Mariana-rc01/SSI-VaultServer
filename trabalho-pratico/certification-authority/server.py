"""
Simple TLS Server.
- If they don't already exist, generates a key and CSR.
- Contacts the CA daemon to obtain the signed certificate.
- Starts a TLS server that echoes received messages.
"""

import os
import socket
import ssl

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime

# CA daemon address
CA_DAEMON_HOST = "localhost"
CA_DAEMON_PORT = 8000

# Server files
SERVER_KEY_FILE = "server_key.crt"
SERVER_CSR_FILE = "server_csr.crt"
SERVER_CERT_FILE = "server_cert.crt"

def generate_key_and_csr(common_name="localhost"):
    """
    Generates a key pair and a CSR for the server.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"VAULT Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"{}".format(common_name)),
    ])).sign(key, hashes.SHA256())
    return key, csr

def save_key_and_csr(key, csr):
    # Saves the private key
    with open(SERVER_KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
    # Saves the CSR
    with open(SERVER_CSR_FILE, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

def request_certificate(csr_pem):
    """
    Contacts the CA daemon to obtain the signed certificate.
    """
    import socket
    with socket.create_connection((CA_DAEMON_HOST, CA_DAEMON_PORT)) as sock:
        sock.sendall(csr_pem)
        sock.shutdown(socket.SHUT_WR)
        # Reads the response (assuming the certificate fits in 8KB)
        received = sock.recv(8192)
        return received

def ensure_certificate():
    """
    Checks if the server files exist; if not, generates and obtains the certificate.
    """
    if os.path.exists(SERVER_KEY_FILE) and os.path.exists(SERVER_CSR_FILE) and os.path.exists(SERVER_CERT_FILE):
        print("Server key, CSR, and certificate already exist.")
        return
    key, csr = generate_key_and_csr()
    save_key_and_csr(key, csr)
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    cert_pem = request_certificate(csr_pem)
    with open(SERVER_CERT_FILE, "wb") as f:
        f.write(cert_pem)
    print("Server certificate obtained from the CA daemon.")

def start_tls_server(host="localhost", port=8443):
    """
    Starts the TLS server.
    """
    ensure_certificate()
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=SERVER_CERT_FILE, keyfile=SERVER_KEY_FILE)
    # In our example, we do not require client authentication
    bindsocket = socket.socket()
    bindsocket.bind((host, port))
    bindsocket.listen(5)
    print(f"TLS server listening on {host}:{port}")
    try:
        while True:
            newsocket, fromaddr = bindsocket.accept()
            conn = context.wrap_socket(newsocket, server_side=True)
            try:
                data = conn.recv(1024)
                print("Message received:", data.decode())
                conn.sendall(b"Echo: " + data)
            except Exception as e:
                print("Connection error:", e)
            finally:
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
    except KeyboardInterrupt:
        print("Server shutting down.")

if __name__ == "__main__":
    start_tls_server()

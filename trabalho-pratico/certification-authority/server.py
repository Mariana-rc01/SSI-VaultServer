"""
Servidor TLS Simples.
- Se ainda não existirem, gera chave e CSR.
- Contacta o CA daemon para obter o certificado assinado.
- Inicia um servidor TLS que ecoa mensagens recebidas.
"""

import os
import socket
import ssl

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime

# Endereço do CA daemon
CA_DAEMON_HOST = "localhost"
CA_DAEMON_PORT = 8000

# Ficheiros do servidor
SERVER_KEY_FILE = "server_key.pem"
SERVER_CSR_FILE = "server_csr.pem"
SERVER_CERT_FILE = "server_cert.pem"

def generate_key_and_csr(common_name="server.local"):
    """
    Gera um par de chaves e um CSR para o servidor.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyServerOrg"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"{}".format(common_name)),
    ])).sign(key, hashes.SHA256())
    return key, csr

def save_key_and_csr(key, csr):
    # Guarda a chave privada
    with open(SERVER_KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
    # Guarda o CSR
    with open(SERVER_CSR_FILE, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

def request_certificate(csr_pem):
    """
    Contacta o CA daemon para obter o certificado assinado.
    """
    import socket
    with socket.create_connection((CA_DAEMON_HOST, CA_DAEMON_PORT)) as sock:
        sock.sendall(csr_pem)
        sock.shutdown(socket.SHUT_WR)
        # Lê a resposta (assumindo que o certificado cabe em 8KB)
        received = sock.recv(8192)
        return received

def ensure_certificate():
    """
    Verifica se os ficheiros do servidor existem; se não, gera e obtém o certificado.
    """
    if os.path.exists(SERVER_KEY_FILE) and os.path.exists(SERVER_CSR_FILE) and os.path.exists(SERVER_CERT_FILE):
        print("Chave, CSR e certificado do servidor já existem.")
        return
    key, csr = generate_key_and_csr()
    save_key_and_csr(key, csr)
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    cert_pem = request_certificate(csr_pem)
    with open(SERVER_CERT_FILE, "wb") as f:
        f.write(cert_pem)
    print("Certificado do servidor obtido a partir do CA daemon.")

def start_tls_server(host="localhost", port=8443):
    """
    Inicia o servidor TLS.
    """
    ensure_certificate()
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=SERVER_CERT_FILE, keyfile=SERVER_KEY_FILE)
    # No nosso exemplo não exigimos autenticação de cliente
    bindsocket = socket.socket()
    bindsocket.bind((host, port))
    bindsocket.listen(5)
    print(f"Servidor TLS à escuta em {host}:{port}")
    try:
        while True:
            newsocket, fromaddr = bindsocket.accept()
            conn = context.wrap_socket(newsocket, server_side=True)
            try:
                data = conn.recv(1024)
                print("Mensagem recebida:", data.decode())
                conn.sendall(b"Echo: " + data)
            except Exception as e:
                print("Erro na conexão:", e)
            finally:
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
    except KeyboardInterrupt:
        print("Servidor a terminar.")

if __name__ == "__main__":
    start_tls_server()

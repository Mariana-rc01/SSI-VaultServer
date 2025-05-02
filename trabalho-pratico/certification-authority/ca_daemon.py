"""
CA Daemon - Signs Certificate Signing Requests (CSR) and provides a handshake response for one-way validation.

This module stores the CA's private key and certificate in a PKCS#12 (.p12) file located in the "db" directory.
It listens on a TCP socket (default: localhost:8000) to:
  - Respond to a handshake "HELLO" request by sending back:
      • The greeting ("HELLO")
      • The signature of the greeting (using its RSA private key)
      • The CA's certificate in PEM format
  - Process CSRs (in PEM) and return the signed certificate (in PEM)
"""

import os
import socketserver
from datetime import datetime, timedelta
from typing import Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    serialize_key_and_certificates,
    load_key_and_certificates,
)

# Configuration Constants
DB_DIR: str = "db"
CA_P12_FILE: str = os.path.join(DB_DIR, "ca.p12")
CA_P12_PASSWORD: bytes = b"capassword"
CA_CERT_VALIDITY_DAYS: int = 365
HANDSHAKE_GREETING: bytes = b"HELLO"

def ensure_db_directory() -> None:
    """
    Ensure that the directory for storing certificates exists.
    """
    if not os.path.exists(DB_DIR):
        os.makedirs(DB_DIR)
        print(f"Directory '{DB_DIR}' created for storing certificates.")

def create_ca_certificate() -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """
    Creates a new RSA private key and self-signed certificate for the CA.
    """
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Grupo 2 SSI"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Our CA"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Braga"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Braga"),
        x509.NameAttribute(NameOID.PSEUDONYM, u"Our CA"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=CA_CERT_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return ca_key, ca_cert

def load_or_create_ca() -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """
    Loads the CA from the PKCS#12 file if it exists; otherwise, creates a new CA certificate and saves it.
    """
    ensure_db_directory()
    if os.path.exists(CA_P12_FILE):
        with open(CA_P12_FILE, "rb") as f:
            p12 = load_key_and_certificates(f.read(), CA_P12_PASSWORD)
            ca_key = p12[0]
            ca_cert = p12[1]
            print("CA loaded from p12 file.")
    else:
        ca_key, ca_cert = create_ca_certificate()
        p12_bytes = serialize_key_and_certificates(
            name=b"ca",
            key=ca_key,
            cert=ca_cert,
            cas=None,
            encryption_algorithm=serialization.BestAvailableEncryption(CA_P12_PASSWORD)
        )
        with open(CA_P12_FILE, "wb") as f:
            f.write(p12_bytes)
        print("New CA created and saved to p12 file.")
    return ca_key, ca_cert

def sign_message(message: bytes, ca_key: rsa.RSAPrivateKey) -> bytes:
    """
    Signs the given message using the CA's RSA private key.
    """
    signature = ca_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

def sign_csr(ca_key: rsa.RSAPrivateKey, ca_cert: x509.Certificate,
             csr: x509.CertificateSigningRequest) -> x509.Certificate:
    """
    Signs a Certificate Signing Request (CSR) using the CA's key and certificate.
    """
    subject = csr.subject
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=180))
    )
    certificate = cert_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return certificate

class CADaemonHandler(socketserver.StreamRequestHandler):
    """
    Request handler for the CA daemon.
    
    If the client sends a handshake greeting ("HELLO"), the daemon signs the greeting and returns:
      - The greeting
      - The signature (hex-encoded)
      - The CA certificate in PEM format.
    Otherwise, it treats the incoming data as a CSR in PEM, signs it, and returns the signed certificate (in PEM).
    """
    def handle(self) -> None:
        try:
            data = self.rfile.read()
            if not data:
                return

            if data.strip() == HANDSHAKE_GREETING:
                self.handle_handshake()
            else:
                self.handle_csr(data)
        except Exception as e:
            print("Error handling request:", e)
            error_msg = f"Error processing request: {e}".encode()
            self.wfile.write(error_msg)

    def handle_handshake(self) -> None:
        """
        Handles the handshake request by signing the greeting and sending:
          - The greeting
          - The signature (in hex)
          - The CA certificate in PEM
        """
        ca_key = self.server.ca_key
        ca_cert = self.server.ca_cert
        signature = sign_message(HANDSHAKE_GREETING, ca_key)
        response_parts = [
            HANDSHAKE_GREETING,
            signature.hex().encode(),
            ca_cert.public_bytes(encoding=serialization.Encoding.PEM)
        ]
        response = b"\n".join(response_parts)
        self.wfile.write(response)
        print("Handshake completed and sent to client.")

    def handle_csr(self, data: bytes) -> None:
        """
        Processes a CSR: loads the CSR, signs it, and sends back the signed certificate in PEM.
        """
        csr = x509.load_pem_x509_csr(data)
        signed_cert = sign_csr(self.server.ca_key, self.server.ca_cert, csr)
        pem_cert = signed_cert.public_bytes(encoding=serialization.Encoding.PEM)
        self.wfile.write(pem_cert)
        print("CSR signed and certificate sent.")

class CADaemon(socketserver.ThreadingTCPServer):
    """
    CA daemon that loads the CA and provides handshake and CSR signing functionality.
    """
    allow_reuse_address = True
    def __init__(self, server_address: Tuple[str, int], RequestHandlerClass) -> None:
        super().__init__(server_address, RequestHandlerClass)
        self.ca_key, self.ca_cert = load_or_create_ca()

def run_ca_daemon(host: str = "localhost", port: int = 8000) -> None:
    """
    Runs the CA daemon.
    """
    with CADaemon((host, port), CADaemonHandler) as server:
        print(f"CA Daemon running on {host}:{port}")
        server.serve_forever()

if __name__ == "__main__":
    run_ca_daemon()

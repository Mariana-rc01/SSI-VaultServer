"""
CA Daemon - Signs Certificate Signing Requests (CSR)
Stores the CA's private key and certificate in a PKCS#12 (.p12) file.
Listens on a TCP socket (default localhost:8000) to receive CSRs (PEM)
and returns the signed certificate (PEM).
"""

import os
import socketserver
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    serialize_key_and_certificates,
    load_key_and_certificates,
)

# Configuration
CA_P12_FILE = "ca.p12"
CA_P12_PASSWORD = b"capassword"
CA_CERT_VALIDITY_DAYS = 365

def create_ca_certificate():
    """
    Creates a private key and a self-signed certificate for the CA.
    """
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Grupo 2 SSI"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Our CA"),
    ])
    ca_cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(issuer) \
        .public_key(ca_key.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(datetime.utcnow()) \
        .not_valid_after(datetime.utcnow() + timedelta(days=CA_CERT_VALIDITY_DAYS)) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
        .sign(ca_key, hashes.SHA256())
    return ca_key, ca_cert

def load_or_create_ca():
    """
    Loads the CA from the p12 file if it exists; otherwise, creates and saves it.
    """
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

class CADaemonHandler(socketserver.StreamRequestHandler):
    """
    CSR request handler.
    Receives a CSR in PEM format, signs it, and returns the signed certificate in PEM format.
    """
    def handle(self):
        try:
            data = self.rfile.read()
            if not data:
                return
            
            # Load the CSR from PEM format
            csr = x509.load_pem_x509_csr(data)
            # Ask the CA to sign the CSR
            signed_cert = self.server.ca_sign(csr)
            pem_cert = signed_cert.public_bytes(encoding=serialization.Encoding.PEM)
            self.wfile.write(pem_cert)
            print("CSR signed and certificate sent.")
        except Exception as e:
            print("Error handling request:", e)
            error_msg = f"Error processing CSR: {e}".encode()
            self.wfile.write(error_msg)

class CADaemon(socketserver.ThreadingTCPServer):
    """
    CA server that, in addition to standard behavior, loads the CA and has the ca_sign method.
    """
    allow_reuse_address = True
    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        self.ca_key, self.ca_cert = load_or_create_ca()

    def ca_sign(self, csr):
        """
        Signs a CSR and returns a certificate.
        """
        subject = csr.subject
        cert_builder = x509.CertificateBuilder() \
            .subject_name(subject) \
            .issuer_name(self.ca_cert.subject) \
            .public_key(csr.public_key()) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(datetime.utcnow()) \
            .not_valid_after(datetime.utcnow() + timedelta(days=180))
        certificate = cert_builder.sign(private_key=self.ca_key, algorithm=hashes.SHA256())
        return certificate

def run_ca_daemon(host="localhost", port=8000):
    with CADaemon((host, port), CADaemonHandler) as server:
        print(f"CA Daemon running on {host}:{port}")
        server.serve_forever()

if __name__ == "__main__":
    run_ca_daemon()

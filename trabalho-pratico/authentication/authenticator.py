import os
import socket
import getpass
from typing import Tuple, Optional

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    serialize_key_and_certificates,
    load_key_and_certificates,
)

# Configuration Constants
DB_DIR: str = "authentication/db"
USER_P12_FORMAT: str = os.path.join(DB_DIR, "VAULT_CLI{username}.p12")
CA_DAEMON_HOST: str = "localhost"       # The CA daemon host
CA_DAEMON_PORT: int = 8000              # The CA daemon port
CERT_VALIDITY_DAYS: int = 180           # Validity (days) for the user certificate
HANDSHAKE_GREETING: bytes = b"HELLO"

def ensure_db_directory() -> None:
    """
    Ensure that the directory for storing .p12 files exists.
    """
    if not os.path.exists(DB_DIR):
        os.makedirs(DB_DIR)
        print(f"Directory '{DB_DIR}' created for storing certificates.")

def generate_private_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """
    Generate a new RSA private key.

    Args:
        key_size: Key size in bits (default 2048).

    Returns:
        An instance of RSAPrivateKey.
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)

def create_csr(private_key: rsa.RSAPrivateKey, common_name: str) -> x509.CertificateSigningRequest:
    """
    Create a CSR for the user.

    Args:
        private_key: User's private key.
        common_name: Username to set as the common name.

    Returns:
        A CSR object.
    """
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256())
    return csr

def send_csr_to_ca(csr: x509.CertificateSigningRequest,
                   ca_host: str = CA_DAEMON_HOST,
                   ca_port: int = CA_DAEMON_PORT) -> x509.Certificate:
    """
    Send the CSR to the CA daemon and receive the signed certificate.

    Prior to sending the CSR, the client performs a handshake with the CA to get its signed greeting and certificate.
    The handshake response is validated before proceeding with the CSR submission.

    Args:
        csr: The CSR to submit.
        ca_host: CA daemon host.
        ca_port: CA daemon port.

    Returns:
        The signed certificate from the CA.
    """
    # First, perform the one-way validation handshake with the CA.
    perform_ca_handshake(ca_host, ca_port)

    pem_csr: bytes = csr.public_bytes(serialization.Encoding.PEM)
    with socket.create_connection((ca_host, ca_port)) as sock:
        sock.sendall(pem_csr)
        sock.shutdown(socket.SHUT_WR)
        response = sock.recv(4096)
    
    try:
        certificate = x509.load_pem_x509_certificate(response)
    except Exception as e:
        raise Exception("Failed to load certificate from CA response: " + str(e))
    return certificate

def perform_ca_handshake(ca_host: str, ca_port: int) -> None:
    """
    Performs a one-way validation handshake with the CA daemon.
    
    The client sends a handshake greeting ("HELLO") and expects a response containing:
      - The same greeting.
      - A signature of the greeting (in hex).
      - The CA certificate in PEM format.
    
    The function verifies the signature using the CA certificate's public key.
    
    Args:
        ca_host: The CA daemon host.
        ca_port: The CA daemon port.
    
    Raises:
        Exception: If the handshake response is invalid or the signature verification fails.
    """
    with socket.create_connection((ca_host, ca_port)) as sock:
        # Send handshake greeting
        sock.sendall(HANDSHAKE_GREETING)
        sock.shutdown(socket.SHUT_WR)
        response = sock.recv(4096)
    
    # Expecting a response of three parts separated by newlines
    parts = response.split(b"\n", 2)
    if len(parts) < 3:
        raise Exception("Incomplete handshake response from CA.")
    
    recv_greeting, signature_hex, ca_cert_pem = parts[0], parts[1], parts[2]
    if recv_greeting.strip() != HANDSHAKE_GREETING:
        raise Exception("Handshake greeting mismatch.")

    # Load the CA certificate from the received PEM
    try:
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    except Exception as e:
        raise Exception("Failed to load CA certificate from handshake response: " + str(e))
    
    # Convert the signature from hex to bytes
    try:
        signature = bytes.fromhex(signature_hex.decode())
    except Exception as e:
        raise Exception("Invalid signature format in handshake response: " + str(e))
    
    # Verify the signature of the greeting using the CA's public key
    try:
        ca_cert.public_key().verify(
            signature,
            HANDSHAKE_GREETING,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except Exception as e:
        raise Exception("CA handshake signature verification failed: " + str(e))
    
    print("CA handshake validation succeeded.")

def save_p12_file(file_path: str,
                  name: bytes,
                  private_key: rsa.RSAPrivateKey,
                  certificate: x509.Certificate,
                  password: bytes) -> None:
    """
    Save the user's private key and certificate in a PKCS#12 file.

    Args:
        file_path: Path to save the .p12 file.
        name: Identifier name to store in the PKCS#12 file.
        private_key: The user's private key.
        certificate: The user's certificate.
        password: The password to encrypt the .p12 file.
    """
    p12_data: bytes = serialize_key_and_certificates(
        name=name,
        key=private_key,
        cert=certificate,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )
    with open(file_path, 'wb') as f:
        f.write(p12_data)

def load_p12_file(file_path: str, password: bytes) -> Tuple[Optional[rsa.RSAPrivateKey], Optional[x509.Certificate]]:
    """
    Loads a PKCS#12 file to retrieve the user's private key and certificate.

    Args:
        file_path: The path to the .p12 file.
        password: The password to decrypt the file.

    Returns:
        A tuple (private_key, certificate) if successful; otherwise, (None, None).
    """
    if not os.path.exists(file_path):
        return None, None

    with open(file_path, 'rb') as f:
        p12_data = f.read()
    p12 = load_key_and_certificates(p12_data, password)
    private_key = p12[0]
    certificate = p12[1]
    return private_key, certificate

def load_or_create_user_certificate(username: str,
                                    p12_password: bytes,
                                    ca_host: str = CA_DAEMON_HOST,
                                    ca_port: int = CA_DAEMON_PORT) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """
    Loads an existing .p12 file for the user or creates a new certificate if not found.

    If the file does not exist, the function:
      1. Generates a new RSA private key.
      2. Creates a CSR using the username as the common name.
      3. Sends the CSR to the CA (after a successful handshake) to obtain a signed certificate.
      4. Saves the new .p12 file.

    Args:
        username: The user's username.
        p12_password: The password used to encrypt the .p12 file.
        ca_host: The CA daemon host.
        ca_port: The CA daemon port.

    Returns:
        A tuple (private_key, certificate) for the user.
    """
    ensure_db_directory()
    file_path: str = USER_P12_FORMAT.format(username=username)
    private_key, certificate = load_p12_file(file_path, p12_password)
    if private_key is not None and certificate is not None:
        print(f"Existing certificate loaded from '{file_path}'.")
        return private_key, certificate

    print(f"Creating a new certificate for user '{username}'.")
    private_key = generate_private_key()
    csr = create_csr(private_key, common_name=username)
    certificate = send_csr_to_ca(csr, ca_host, ca_port)
    save_p12_file(file_path, name=f"VAULT_CLI{username}".encode(),
                  private_key=private_key, certificate=certificate, password=p12_password)
    print(f"New certificate saved in '{file_path}'.")
    return private_key, certificate

def terminal_interface() -> Tuple[Optional[rsa.RSAPrivateKey], Optional[x509.Certificate]]:
    """
    Provides a simple terminal interface for login and account creation.
    The user can choose to log in (load an existing certificate) or create a new account.
    """
    print("====================================")
    print("       Welcome to Vault CLI         ")
    print("====================================")
    print("Please choose an option:")
    print("1. Login")
    print("2. Create new account")
    choice = input("Enter your choice (1 or 2): ").strip()

    if choice not in ["1", "2"]:
        print("Invalid option selected. Exiting the program.")
        return None, None

    username: str = input("Enter your username: ").strip()
    password_input: str = getpass.getpass("Enter your password: ")
    p12_password: bytes = password_input.encode()
    if len(p12_password) < 1:
        print("Invalid login. Password field can't be empty.")
        return None, None

    try:
        if choice == "1":
            file_path = USER_P12_FORMAT.format(username=username)
            private_key, certificate = load_p12_file(file_path, p12_password)
            if private_key is None or certificate is None:
                print("Account not found. Please create a new account first.")
                return None, None
            print("Login successful!")
        elif choice == "2":
            private_key, certificate = load_or_create_user_certificate(username, p12_password)
            print("Account created and logged in successfully!")

        print("\nCertificate Details:")
        print(f"Subject: {certificate.subject}")
        print(f"Issuer: {certificate.issuer}")
        print(f"Valid From: {certificate.not_valid_before_utc}")
        print(f"Valid Until: {certificate.not_valid_after_utc}")

        return private_key, certificate
    except Exception as e:
        print("Error during authentication process:", e)

def main() -> None:
    """
    Main function that starts the terminal interface for authentication.

    Can be called independently to verify validities manually.
    """
    terminal_interface()

if __name__ == "__main__":
    main()

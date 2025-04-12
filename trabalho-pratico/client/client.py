import asyncio
import json
import base64
import argparse
from typing import Optional, Union

from utils.utils import (
    generate_derived_key,
    generate_private_key,
    generate_public_key,
    serialize_public_key,
    deserialize_public_key,
    generate_shared_key,
    encrypt,
    decrypt,
    build_aesgcm,
    request,
    certificate_create,
    is_certificate_valid,
    is_signature_valid,
    sign_message_with_rsa,
    serialize_certificate,
    serialize_to_bytes,
    deserialize_from_bytes,
    serialize_response,
    ClientFirstInteraction
)
from client.utils import add, read
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from cryptography.x509 import Certificate
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.dh import DHPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

conn_port: int = 7777
max_msg_size: int = 9999


class Client:
    """Class that implements the functionality of a CLIENT."""

    def __init__(
        self,
        sckt: Optional[tuple[str, int]] = None,
        rsa_private_key: Optional[RSAPrivateKey] = None,
        client_certificate: Optional[Certificate] = None,
    ) -> None:
        """Class constructor."""
        self.sckt = sckt
        self.msg_cnt: int = 0
        self.aesgcm: Optional[AESGCM] = None
        self.last_command: Optional[str] = None
        self.rsa_private_key = rsa_private_key
        self.client_certificate = client_certificate

    async def handshake(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Performs the handshake with the server."""
        # Send public key to the server
        dh_private_key: DHPrivateKey = generate_private_key()
        dh_public_key: EllipticCurvePublicKey = generate_public_key(dh_private_key)
        serialized_public_key: bytes = serialize_public_key(dh_public_key)

        # Encode the public key in Base64 before sending
        serialized_public_key_json: bytes = serialize_response(ClientFirstInteraction(base64.b64encode(serialized_public_key).decode()))
        writer.write(serialized_public_key_json)
        await writer.drain()

        # Receive server's public key, certificate, and signature
        response: bytes = await reader.read(max_msg_size)
        print(f"Received request: {request}")
        if not response:
            print("Error: Received empty response during handshake.")
            return
        response_data: dict = deserialize_from_bytes(response)
        serialized_server_public_key: bytes = base64.b64decode(response_data["public_key"])
        server_certificate: bytes = base64.b64decode(response_data["certificate"])
        server_signature: bytes = base64.b64decode(response_data["signature"])

        server_public_key: EllipticCurvePublicKey = deserialize_public_key(serialized_server_public_key)
        server_certificate_obj: Certificate = certificate_create(server_certificate)

        # Validate certificate
        certificate_valid: bool = is_certificate_valid(server_certificate_obj, "SSI Vault Server")
        if not certificate_valid:
            # Abort connection
            print("Aborting handshake...")
            return

        # Extract server's public key from certificate
        server_certificate_public_key = server_certificate_obj.public_key()

        # Validate signature
        both_public_keys: bytes = serialized_public_key + serialized_server_public_key
        signature_valid: bool = is_signature_valid(
            server_signature, both_public_keys, server_certificate_public_key
        )
        if not signature_valid:
            # Abort connection
            print("Aborting handshake...")
            return

        # Derived shared key
        shared_key: bytes = generate_shared_key(dh_private_key, server_public_key)
        derived_key: bytes = generate_derived_key(shared_key)
        self.aesgcm = build_aesgcm(derived_key)

        # Send client certificate and signature to the server
        client_signature: bytes = sign_message_with_rsa(both_public_keys, self.rsa_private_key)
        client_certificate_subject: str = self.client_certificate.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME
        )[0].value
        writer.write(
            serialize_to_bytes(
                {
                    "signature": base64.b64encode(client_signature).decode(),
                    "certificate": base64.b64encode(serialize_certificate(self.client_certificate)).decode(),
                    "subject": base64.b64encode(client_certificate_subject.encode()).decode(),
                }
            )
        )
        await writer.drain()

        print("Handshake completed!")

    def process(self, msg: bytes = b"") -> Optional[bytes]:
        """Processes a message (`bytestring`) sent by the SERVER.
        Returns the message to be sent as a response (`None` to
        terminate the connection)."""
        if len(msg) != 0:
            self.msg_cnt += 1
            try:
                decrypted_msg: bytes = decrypt(msg, self.aesgcm)
                print(f"[DEBUG] Decrypted message ({self.msg_cnt}): {decrypted_msg}")
                response_data: dict = deserialize_from_bytes(decrypted_msg)
                print("VER AQUI O RESPONSE DATA")
                print(response_data)

                if self.last_command == "read":
                    read(decrypted_msg, self.rsa_private_key)
                    self.last_command = None
                else:
                    print("Received (%d): %r" % (self.msg_cnt, response_data))
            except Exception as e:
                print(f"[ERROR] Failed to process message ({self.msg_cnt}): {e}")
                return None

        print("\nCommand [add <file-path> | read <file-id> | exit]:")
        new_msg: str = input().strip()
        if new_msg.startswith("add "):
            self.last_command = "add"
            file_path: str = new_msg.split(" ", 1)[1]

            client_public_key = self.rsa_private_key.public_key()
            json_bytes: Optional[bytes] = add(file_path, client_public_key)
            if not json_bytes:
                return b""

            return encrypt(json_bytes, self.aesgcm)
        elif new_msg.startswith("read "):
            self.last_command = "read"
            file_id: str = new_msg.split(" ", 1)[1]

            read_request: dict = request("read", [file_id])
            json_bytes: bytes = serialize_to_bytes(read_request)

            return encrypt(json_bytes, self.aesgcm)
        elif new_msg.strip() == "exit":
            return None
        else:
            print("Invalid command.")
            return b""


# Client/Server functionality
async def tcp_echo_client(args: argparse.Namespace) -> None:
    """Establishes the connection with the server and handles communication."""

    # Load the PKCS#12 file
    with open(args.p12_path, "rb") as p12_file:
        p12_data: bytes = p12_file.read()

    password: Optional[bytes] = args.password.encode() if args.password else None
    private_key: RSAPrivateKey
    certificate: Certificate
    private_key, certificate, _ = load_key_and_certificates(p12_data, password)

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    reader, writer = await asyncio.open_connection("127.0.0.1", conn_port)
    addr: tuple[str, int] = writer.get_extra_info("peername")
    client: Client = Client(addr, rsa_private_key=private_key, client_certificate=certificate)

    await client.handshake(reader, writer)
    if client.aesgcm is None:
        return

    msg: Optional[bytes] = client.process()
    while msg:
        writer.write(msg)
        msg = await reader.read(max_msg_size)
        if msg:
            msg = client.process(msg)
        else:
            break
    writer.write(b"\n")
    print("Socket closed!")
    writer.close()


def run_client() -> None:
    """Runs the client event loop."""
    parser: argparse.ArgumentParser = argparse.ArgumentParser(description="Client for secure communication.")
    parser.add_argument("p12_path", help="Path to the PKCS#12 file (.p12)")
    parser.add_argument("--password", help="Password for the PKCS#12 file", default="")
    args: argparse.Namespace = parser.parse_args()

    loop: asyncio.AbstractEventLoop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client(args))


run_client()

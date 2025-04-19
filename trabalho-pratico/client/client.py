import asyncio
import base64
import argparse
from typing import Optional

from authentication.authenticator import terminal_interface

from utils.utils import (
    GroupCreateResponse,
    ListResponse,
    ShareResponse,
    VaultError,
    ClientFirstInteraction,
    ServerFirstInteraction,
    ClientSecondInteraction,
    AddResponse,
    ReadResponse,
    generate_derived_key,
    generate_private_key,
    generate_public_key,
    serialize_public_key,
    deserialize_public_key,
    generate_shared_key,
    encrypt,
    decrypt,
    build_aesgcm,
    certificate_create,
    is_certificate_valid,
    is_signature_valid,
    sign_message_with_rsa,
    serialize_certificate,
    serialize_response,
    deserialize_request,
)
from client.utils import addRequest, groupCreateRequest, listRequest, listResponse, readRequest, readResponse, shareRequest
from cryptography.x509 import Certificate
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.dh import DHPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

conn_port: int = 7777
max_msg_size: int = 9999

SERVER_COMMOM_NAME: str = "S"

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
        self.rsa_private_key = rsa_private_key
        self.client_certificate = client_certificate
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None

    async def handshake(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.reader = reader
        self.writer = writer
        """Performs the handshake with the server."""
        # Send public key to the server
        dh_private_key: DHPrivateKey = generate_private_key()
        dh_public_key: EllipticCurvePublicKey = generate_public_key(dh_private_key)
        serialized_public_key: bytes = serialize_public_key(dh_public_key)

        # Encode the public key in Base64 before sending
        serialized_public_key_json: bytes = serialize_response(ClientFirstInteraction(base64.b64encode(serialized_public_key).decode()))
        writer.write(serialized_public_key_json)
        await writer.drain()

        # Receive server's public key, signature, and certificate
        response = await reader.read(max_msg_size)
        response_data: ServerFirstInteraction = deserialize_request(response)
        serialized_server_public_key: bytes = base64.b64decode(response_data.public_key)
        server_signature: bytes = base64.b64decode(response_data.signature)
        server_certificate: bytes = base64.b64decode(response_data.certificate)

        server_public_key: EllipticCurvePublicKey = deserialize_public_key(serialized_server_public_key)
        server_certificate_obj: Certificate = certificate_create(server_certificate)

        # Validate certificate
        certificate_valid: bool = is_certificate_valid(server_certificate_obj, SERVER_COMMOM_NAME)
        if not certificate_valid:
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

        response_tosend = ClientSecondInteraction(base64.b64encode(client_signature).decode(), 
                                                  base64.b64encode(serialize_certificate(self.client_certificate)).decode(),
                                                  base64.b64encode(client_certificate_subject.encode()).decode())

        # Send client's certificate and signature
        writer.write(serialize_response(response_tosend))
        await writer.drain()

        print("Handshake completed!")

    async def process(self, msg: bytes = b"") -> Optional[bytes]:
        """Processes a message (`bytestring`) sent by the SERVER.
        Returns the message to be sent as a response (`None` to
        terminate the connection)."""
        if len(msg) != 0:
            self.msg_cnt += 1
            try:
                decrypted_msg: bytes = decrypt(msg, self.aesgcm)
                server_response = deserialize_request(decrypted_msg)

                if isinstance(server_response, ReadResponse):
                    readResponse(server_response, self.rsa_private_key)

                elif isinstance(server_response, AddResponse):
                    print(f"Received {server_response.response}")

                elif isinstance(server_response, ListResponse):
                    listResponse(server_response)

                elif isinstance(server_response, ShareResponse):
                    print(f"Received {server_response.response}")

                elif isinstance(server_response, GroupCreateResponse):
                    print(f"Received {server_response.response}")

                elif isinstance(server_response, VaultError):
                    print(f"Error: {server_response.error}")

                else:
                    print(f"Unknown response type: {type(server_response)}")
                    return None

            except Exception as e:
                print(f"[ERROR] Failed to process message ({self.msg_cnt}): {e}")
                return None

        print("\nPlease choose an command:")
        print("- add <file-path>")
        print("- read <file-id>")
        print("- list [-u <user-id> | -g <group-id>]")
        print("- share <file-id> <user-id> <permission>")
        print("- group create <group-name>")
        print("- exit")
        new_msg: str = input().strip()
        if new_msg.startswith("add "):
            file_path: str = new_msg.split(" ", 1)[1]

            client_public_key = self.rsa_private_key.public_key()

            json_bytes: Optional[bytes] = addRequest(file_path, client_public_key)
            if not json_bytes:
                return b""

            return encrypt(json_bytes, self.aesgcm)
        elif new_msg.startswith("read "):
            file_id: str = new_msg.split(" ", 1)[1]

            json_bytes: bytes = readRequest(file_id)
            if not json_bytes:
                return b""

            return encrypt(json_bytes, self.aesgcm)
        elif new_msg.startswith("list"):
            args = new_msg.split()
            list_type = None
            target_id = None

            if len(args) >= 2:
                if args[1] == "-u" and len(args) == 3:
                    list_type = "user"
                    target_id = args[2]
                elif args[1] == "-g" and len(args) == 3:
                    list_type = "group"
                    target_id = args[2]

            json_bytes: bytes = listRequest(list_type, target_id)
            if not json_bytes:
                return b""

            return encrypt(json_bytes, self.aesgcm)
        elif new_msg.startswith("share "):
            args = new_msg.split()
            if len(args) != 4:
                print("Invalid command.")
                return b""

            file_id: str = args[1]
            target_id: str = args[2]
            permission: str = args[3].upper()

            try:
                share_request = await shareRequest(
                    file_id,
                    target_id,
                    permission,
                    self.rsa_private_key,
                    self.aesgcm,
                    self.writer,
                    self.reader,
                )
                return encrypt(share_request, self.aesgcm)
            except Exception as e:
                print(f"Error during share request: {e}")
                return b""
        elif new_msg.startswith("group create "):
            group_name: str = new_msg.split(" ", 2)[2]

            json_bytes: bytes = groupCreateRequest(group_name)
            if not json_bytes:
                return b""

            return encrypt(json_bytes, self.aesgcm)
        elif new_msg.strip() == "exit":
            return None
        else:
            print("Invalid command.")
            return b""


# Client/Server functionality
async def tcp_echo_client() -> None:
    """Establishes the connection with the server and handles communication."""

    private_key: RSAPrivateKey
    certificate: Certificate
    private_key, certificate = terminal_interface()

    if private_key is None or Certificate is None:
        return

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    reader, writer = await asyncio.open_connection("127.0.0.1", conn_port)
    addr: tuple[str, int] = writer.get_extra_info("peername")
    client: Client = Client(addr, rsa_private_key=private_key, client_certificate=certificate)

    await client.handshake(reader, writer)
    if client.aesgcm is None:
        return

    msg: Optional[bytes] = await client.process()
    while msg:
        writer.write(msg)
        msg = await reader.read(max_msg_size)
        if msg:
            msg = await client.process(msg)
        else:
            break
    writer.write(b"\n")
    print("Socket closed!")
    writer.close()


def run_client() -> None:
    """Runs the client event loop."""
    loop: asyncio.AbstractEventLoop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())


run_client()

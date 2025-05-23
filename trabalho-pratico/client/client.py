import argparse
import asyncio, base64
from typing import Optional
import readline

from authentication.authenticator import terminal_interface

from client.notifications import print_notifications
from utils.utils import *
from utils.data_structures import *
from client.utils import *
from cryptography.x509 import Certificate
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

conn_port: int = 7777

SERVER_COMMOM_NAME: str = "S"

COMMANDS = [
    'add', 'delete', 'revoke', 'read', 'list', 'details',
    'replace', 'share',
    'group list', 'group delete', 'group create', 'group add',
    'group add-user', 'group delete-user',
    'exit'
]

def completer(text, state):
    # Complete only at beginning of line
    results =  [x for x in COMMANDS if x.startswith(text)] + [None]
    return results[state]

readline.set_completer(completer)
# Bind Tab and Right Arrow for completion; fallback to Ctrl-I on macOS libedit
try:
    readline.parse_and_bind('tab: complete')
except Exception:
    readline.parse_and_bind(r'"\C-i": complete')

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
        self.cipher: Optional[AESGCM] = None
        self.rsa_private_key = rsa_private_key
        self.client_certificate = client_certificate

    async def handshake(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tls_option: str
    ) -> None:
        """Performs the handshake with the server."""
        # Send public key to the server
        client_version, cipher_suites, use_ecdh, client_random = prepare_tls_client_context(tls_option)

        client_private_key = generate_private_key(use_ecdh)
        client_public_key = generate_public_key(client_private_key)
        serialized_public_key: bytes = serialize_public_key(client_public_key)

        client_hello = ClientHello(
            tls_version   = client_version,
            client_random = base64.b64encode(client_random).decode(),
            cipher_suites = cipher_suites,
            public_key    = base64.b64encode(serialized_public_key).decode()
        )

        # Encode the public key in Base64 before sending
        serialized_public_key_json: bytes = serialize_response(client_hello)
        writer.write(serialized_public_key_json)
        await writer.drain()

        # Receive server's public key, signature, and certificate
        response = await reader.read(max_msg_size)
        response_data: ServerHello = deserialize_request(response)
        serialized_server_public_key: bytes = base64.b64decode(response_data.public_key)
        server_signature: bytes = base64.b64decode(response_data.signature)
        server_certificate: bytes = base64.b64decode(response_data.certificate)
        server_random = base64.b64decode(response_data.server_random)
        server_public_key = deserialize_public_key(serialized_server_public_key)
        server_certificate_obj: Certificate = certificate_create(server_certificate)

        # Validate certificate
        certificate_valid: bool = is_certificate_valid(server_certificate_obj, SERVER_COMMOM_NAME)
        if not certificate_valid:
            print("Aborting handshake...")
            return

        # Extract server's public key from certificate
        server_certificate_public_key = server_certificate_obj.public_key()

        # Validate signature
        handshake_data: bytes = (
            client_random +
            server_random +
            base64.b64decode(client_hello.public_key) +
            serialized_server_public_key +
            response_data.selected_cipher.encode()
        )
        signature_valid: bool = is_signature_valid(
            server_signature, handshake_data, server_certificate_public_key
        )
        if not signature_valid:
            print("Aborting handshake...")
            return

        # Derived shared key
        shared_key: bytes = generate_shared_key(client_private_key, server_public_key)
        derived_key: bytes = generate_derived_key(shared_key + client_random + server_random, response_data.selected_cipher)
        self.cipher = build_method(derived_key, response_data.selected_cipher)

        # Send client certificate and signature to the server
        client_signature: bytes = sign_message_with_rsa(handshake_data, self.rsa_private_key)
        client_certificate_subject: str = self.client_certificate.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME
        )[0].value

        response_tosend = ClientAuthentication(base64.b64encode(client_signature).decode(),
                                               base64.b64encode(serialize_certificate(self.client_certificate)).decode(),
                                               base64.b64encode(client_certificate_subject.encode()).decode())

        # Send client's certificate and signature
        writer.write(serialize_response(response_tosend))
        await writer.drain()

        print("Handshake completed!")

    async def receive_notifications(self, reader: asyncio.StreamReader) -> None:
        """Receives notifications from the server."""
        try:
            notifications = await reader.read(max_msg_size)
            if not notifications:
                print("No notifications received.")
                return
            decrypted_notification: bytes = decrypt(notifications, self.cipher)
            notification_obj = deserialize_request(decrypted_notification)
            print_notifications(notification_obj)
        except Exception as e:
            print(f"Error receiving notification: {e}")

    async def process(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, msg: bytes = b"") -> Optional[bytes]:
        """Processes a message (`bytestring`) sent by the SERVER.
        Returns the message to be sent as a response (`None` to
        terminate the connection)."""
        while True:
            if len(msg) != 0:
                self.msg_cnt += 1
                try:
                    decrypted_msg: bytes = decrypt(msg, self.cipher)
                    server_response = deserialize_request(decrypted_msg)

                    if isinstance(server_response, ReadResponse):
                        readResponse(server_response, self.rsa_private_key)
                        msg = b""

                    elif isinstance(server_response, AddResponse):
                        print(f"Received {server_response.response}")
                        msg = b""

                    elif isinstance(server_response, ListResponse):
                        listResponse(server_response)
                        msg = b""

                    elif isinstance(server_response, ShareResponse):
                        print(f"Received {server_response.response}")
                        msg = b""

                    elif isinstance(server_response, DeleteResponse):
                        print(f"Received {server_response.response}")
                        msg = b""

                    elif isinstance(server_response, ReplaceResponse):
                        print(f"Received {server_response.response}")
                        msg = b""

                    elif isinstance(server_response, DetailsResponse):
                        detailsResponse(server_response)
                        msg = b""

                    elif isinstance(server_response, RevokeResponse):
                        print(f"Received {server_response.response}")
                        msg = b""

                    elif isinstance(server_response, GroupCreateResponse):
                        print(f"Received {server_response.response}")
                        msg = b""

                    elif isinstance(server_response, GroupDeleteResponse):
                        print(f"Received {server_response.response}")
                        msg = b""

                    elif isinstance(server_response, GroupAddUserResponse):
                        print(f"Received {server_response.response}")
                        msg = b""

                    elif isinstance(server_response, GroupListResponse):
                        groupList(server_response)
                        msg = b""

                    elif isinstance(server_response, GroupAddResponse):
                        print(f"Received {server_response.response}")
                        msg = b""

                    elif isinstance(server_response, DeleteUserGroupResponse):
                        print(f"Received {server_response.response}")
                        msg = b""

                    elif isinstance(server_response, VaultError):
                        print(f"Error: {server_response.error}")

                    else:
                        print(f"Unknown response type: {type(server_response)}")
                        msg = b""
                        continue

                except Exception as e:
                    print(f"[ERROR] Failed to process message ({self.msg_cnt}): {e}")
                    msg = b""
                    continue

            menu()
            new_msg: str = input(">> ")
            readline.add_history(new_msg)
            new_msg = new_msg.strip()
            if new_msg.startswith("add "):
                file_path: str = new_msg.split(" ", 1)[1]

                client_public_key = self.rsa_private_key.public_key()

                json_bytes: Optional[bytes] = addRequest(file_path, client_public_key)
                if not json_bytes:
                    continue

                return encrypt(json_bytes, self.cipher)
            elif new_msg.startswith("read "):
                file_id: str = new_msg.split(" ", 1)[1]

                json_bytes: bytes = readRequest(file_id)
                if not json_bytes:
                    continue

                return encrypt(json_bytes, self.cipher)
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
                    continue

                return encrypt(json_bytes, self.cipher)
            elif new_msg.startswith("share "):
                args = new_msg.split()
                if len(args) != 4:
                    print("Invalid command.")
                    continue

                file_id: str = args[1]
                target_id: str = args[2]
                permission: str = args[3].upper()

                if permission not in ["R", "W"]:
                    print("Invalid permission.")
                    continue

                try:
                    share_request = await shareRequest(
                        file_id,
                        target_id,
                        permission,
                        self.rsa_private_key,
                        self.cipher,
                        writer,
                        reader,
                    )
                    return encrypt(share_request, self.cipher)
                except Exception as e:
                    print(f"Error during share request: {e}")
                    continue
            elif new_msg.startswith("delete "):
                file_id: str = new_msg.split(" ", 1)[1]

                request = DeleteRequest(file_id)
                json_bytes = serialize_response(request)
                return encrypt(json_bytes, self.cipher)
            elif new_msg.startswith("replace "):
                args = new_msg.split(" ", 2)
                if len(args) != 3:
                    print("Invalid command.")
                    continue

                file_id: str = args[1]
                file_path: str = args[2]

                try:
                    replace_request = await replaceRequest(
                        file_id,
                        file_path,
                        self.rsa_private_key,
                        self.cipher,
                        writer,
                        reader,
                    )
                    return encrypt(replace_request, self.cipher)
                except Exception as e:
                    print(f"Error during replace request: {e}")
                    continue
            elif new_msg.startswith("details "):
                file_id: str = new_msg.split(" ", 1)[1]

                request = DetailsRequest(file_id)
                json_bytes = serialize_response(request)
                return encrypt(json_bytes, self.cipher)
            elif new_msg.startswith("group create "):
                group_name: str = new_msg.split(" ", 2)[2]

                json_bytes: bytes = groupCreateRequest(group_name)
                if not json_bytes:
                    continue

                return encrypt(json_bytes, self.cipher)
            elif new_msg.startswith("group delete "):
                group_id: str = new_msg.split(" ", 2)[2]

                request = GroupDeleteRequest(group_id)
                json_bytes = serialize_response(request)
                return encrypt(json_bytes, self.cipher)
            elif new_msg.startswith("revoke "):
                args = new_msg.split(" ", 2)
                if len(args) != 3:
                    print("Invalid command.")
                    continue

                file_id: str = args[1]
                target_id: str = args[2]

                request = RevokeRequest(file_id, target_id)
                json_bytes = serialize_response(request)
                return encrypt(json_bytes, self.cipher)
            elif new_msg.startswith("group delete-user "):
                args = new_msg.split()

                group_id: str = args[2]
                user_id: str = args[3]

                json_bytes: bytes = deleteGroupUserRequest(group_id, user_id)
                if not json_bytes:
                    return b""
                return encrypt(json_bytes, self.cipher)
            elif new_msg.startswith("group add-user "):
                args = new_msg.split()
                if len(args) != 5:
                    print("Invalid command.")
                    continue

                group_id: str = args[2]
                user_id: str = args[3]
                permission: str = args[4].upper()

                try:
                    groupAddUser_request = await groupAddUserRequest(
                        group_id, user_id, permission, self.rsa_private_key, self.cipher, writer, reader
                    )
                    return encrypt(groupAddUser_request, self.cipher)
                except Exception as e:
                    print(f"Error during share request: {e}")
                    continue
            elif new_msg.startswith("group list"):
                request = GroupListRequest()
                serialized_request = serialize_response(request)
                return encrypt(serialized_request, self.cipher)
            elif new_msg.startswith("group add "):
                args = new_msg[len("group add "):].split(" ", 1)
                if len(args) != 2:
                    print("Invalid command.")
                    continue

                group_id: str = args[0]
                file_path: str = args[1]

                try:
                    group_add_request = await groupAddRequest(
                        file_path,
                        group_id,
                        self.cipher,
                        writer,
                        reader,
                    )
                    return encrypt(group_add_request, self.cipher)
                except Exception as e:
                    print(f"Error during group add request: {e}")
                    continue
            elif new_msg.strip() == "exit":
                return None
            else:
                print("Invalid command.")
                continue


# Client/Server functionality
async def tcp_echo_client(tls_option: str) -> None:
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

    await client.handshake(reader, writer, tls_option)
    if client.cipher is None:
        return

    await client.receive_notifications(reader)

    msg: Optional[bytes] = await client.process(reader, writer)
    while msg:
        writer.write(msg)
        msg = await reader.read(max_msg_size)
        if msg:
            msg = await client.process(reader, writer, msg)
        else:
            break
    writer.write(b"\n")
    print("Socket closed!")
    writer.close()


def run_client() -> None:
    """Runs the client event loop."""
    parser = argparse.ArgumentParser(description="Run the client.")
    parser.add_argument("option", type=str, help="Option to pass to the handshake")
    args = parser.parse_args()

    loop: asyncio.AbstractEventLoop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client(args.option))


run_client()

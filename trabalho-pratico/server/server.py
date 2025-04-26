import asyncio
import os
import base64
import random
from typing import Optional, Tuple
from asyncio.streams import StreamReader, StreamWriter

from utils.utils import *
from server.utils import *
from utils.data_structures import *
from server.notifications import get_notifications, add_notification
from server.utils_db import get_group_public_keys
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates

conn_cnt = 0
conn_port = 7777

STORAGE_DIR = "./storage"
os.makedirs(STORAGE_DIR, exist_ok=True)
DB_DIR = "./db"
os.makedirs(DB_DIR, exist_ok=True)
CERTIFICATE_PATH: str = "authentication/db/VAULT_CLIS.p12"
PASSWORD: str = "S"


class ServerWorker:
    """Class that implements the functionality of the SERVER."""

    def __init__(self, cnt: int, addr: Optional[Tuple[str, int]] = None) -> None:
        """Class constructor."""
        self.id: int = cnt
        self.addr: Optional[Tuple[str, int]] = addr
        self.msg_cnt: int = 0
        self.cipher = None

    async def handshake(self, reader: StreamReader, writer: StreamWriter) -> None:

        with open(CERTIFICATE_PATH, "rb") as p12_file:
            p12_data = p12_file.read()
        rsa_private_key, server_certificate, _ = load_key_and_certificates(p12_data, PASSWORD.encode())

        # Receive client's public key
        request = await reader.read(max_msg_size)
        request_data: ClientHello = deserialize_request(request)
        serialized_client_public_key = base64.b64decode(request_data.public_key)
        client_public_key = deserialize_public_key(serialized_client_public_key)
        client_random = base64.b64decode(request_data.client_random)

        try:
            selected_cipher, use_ecdh = negotiate_cipher(request_data.tls_version, request_data.cipher_suites)
        except ValueError as e:
            print(f"Handshake error: {e}")
            return

        # Generate server's public key and signature
        server_private_key = generate_private_key(use_ecdh)
        server_public_key = generate_public_key(server_private_key)
        serialized_public_key = serialize_public_key(server_public_key)
        server_random = os.urandom(32)

        handshake_data = (
            client_random +
            server_random +
            serialized_client_public_key +
            serialized_public_key +
            selected_cipher.encode()
        )
        signature = sign_message_with_rsa(handshake_data, rsa_private_key)
        serialized_certificate = serialize_certificate(server_certificate)

        response_tosend = ServerHello(public_key      = base64.b64encode(serialized_public_key).decode(),
                                      signature       = base64.b64encode(signature).decode(),
                                      certificate     = base64.b64encode(serialized_certificate).decode(),
                                      server_random   = base64.b64encode(server_random).decode(),
                                      selected_cipher = selected_cipher)

        # Send server's public key, signature, and certificate
        writer.write(serialize_response(response_tosend))
        await writer.drain()

        # Receive client's certificate and signature
        response: bytes = await reader.read(max_msg_size)
        response_data: ClientAuthentication = deserialize_request(response)
        client_signature: bytes = base64.b64decode(response_data.signature)
        client_certificate: bytes = certificate_create(base64.b64decode(response_data.certificate))
        client_subject: bytes = base64.b64decode(response_data.subject).decode()

        # Validate certificate
        certificate_valid = is_certificate_valid(client_certificate, client_subject)
        if not certificate_valid:
            print("Aborting handshake...")
            return

        # Extract client's public key from certificate
        client_certificate_public_key = client_certificate.public_key()

        # Validate signature
        signature_valid = is_signature_valid(client_signature, handshake_data, client_certificate_public_key)
        if not signature_valid:
            print("Aborting handshake...")
            return

        self.id = add_user(client_subject, client_certificate_public_key)

        # Derived shared key
        shared_key = generate_shared_key(server_private_key, client_public_key)
        derived_key = generate_derived_key(shared_key + client_random + server_random, selected_cipher)
        self.cipher = build_method(derived_key, selected_cipher)

    async def send_notifications(self, writer: StreamWriter) -> None:
        notifications = get_notifications(self.id)
        response_data = Notification(notifications)
        writer.write(encrypt(serialize_response(response_data), self.cipher))
        await writer.drain()

    def process(self, msg: bytes) -> Optional[bytes]:
        """Processes a message (`bytestring`) sent by the CLIENT.
        Returns the message to be sent as a response (`None` to
        terminate the connection)."""
        self.msg_cnt += 1
        plaintext = decrypt(msg, self.cipher)

        try:
            client_request = deserialize_request(plaintext)

            if isinstance(client_request, AddRequest):
                request_filename = client_request.filename
                request_filedata = client_request.encrypted_file
                request_encrypted_aes_key = client_request.encrypted_aes_key

                filename = request_filename
                filedata_b64 = request_filedata
                filedata = base64.b64decode(filedata_b64)

                file_id = add_request(filename, filedata, self.id, request_encrypted_aes_key)

                response_data = AddResponse(f"file {filename} added with id: {file_id}")

                return encrypt(serialize_response(response_data), self.cipher)
            elif isinstance(client_request, ReadRequest):
                file_id = client_request.fileid

                file_info = get_file_by_id(file_id)

                if not file_info or not os.path.exists(file_info["location"]):
                    log_request(f"{self.id}", "read", [file_id], "failed", "file not found")
                    return encrypt(f"Error: file {file_id} not found.".encode(), self.cipher)

                user_key = get_user_key(file_info, self.id)

                if not user_key:
                    log_request(f"{self.id}", "read", [file_id], "failed", "no access key")
                    return encrypt(f"Error: no access key for user {self.id}.".encode(), self.cipher)

                with open(file_info["location"], "rb") as f:
                    filedata = f.read()

                response_data = ReadResponse(base64.b64encode(filedata).decode(), user_key)

                log_request(f"{self.id}", "read", [file_id], "success")
                if file_info["owner"] != self.id:
                    add_notification(file_info["owner"], f"User {self.id} read file {file_id}.")
                return encrypt(serialize_response(response_data), self.cipher)
            elif isinstance(client_request, ListRequest):
                files = get_files_for_listing(
                    list_type = client_request.list_type,
                    target_id = client_request.target_id,
                )

                response_data = ListResponse(
                    files = files['personal'],
                    shared = files['shared'],
                    group_files = files['group'],
                )

                log_request(f"{self.id}", "list", [client_request.list_type, client_request.target_id], "success")
                return encrypt(serialize_response(response_data), self.cipher)
            elif isinstance(client_request, DeleteRequest):
                file_id = client_request.file_id
                response = delete_file(file_id, self.id)
                if response is None:
                    return encrypt(serialize_response(VaultError("Error deleting file")), self.cipher)
                return encrypt(serialize_response(DeleteResponse("File deleted successfully")), self.cipher)
            elif isinstance(client_request, ReplaceRequirementsRequest):
                encrypted_key = replace_file_requirements(client_request, self.id)
                if encrypted_key is None:
                    return encrypt(serialize_response(VaultError("Error replacing file")), self.cipher)

                response_data = ReplaceRequirementsResponse(encrypted_key)
                log_request(self.id, "replace", [client_request.file_id], "success")
                return encrypt(serialize_response(response_data), self.cipher)

            elif isinstance(client_request, ReplaceRequest):
                response = replace_file(client_request, self.id)
                if response is None:
                    return encrypt(serialize_response(VaultError("Error replacing file")), self.cipher)

                return encrypt(serialize_response(ReplaceResponse("File replaced successfully")), self.cipher)
            elif isinstance(client_request, DetailsRequest):
                file_id = client_request.file_id
                file_info = get_file_by_id(file_id)

                if not file_info:
                    log_request(f"{self.id}", "details", [file_id], "failed", "file not found")
                    return encrypt(serialize_response(VaultError("File not found")), self.cipher)

                response_data = DetailsResponse(
                    file_id = file_info["id"],
                    file_name = file_info["name"],
                    file_size = file_info["size"],
                    owner = file_info["owner"],
                    permissions = file_info["permissions"],
                    created_at = file_info["created_at"]
                )

                log_request(f"{self.id}", "details", [file_id], "success")
                add_notification(file_info["owner"], f"User {self.id} requested details of file {file_id}.")
                return encrypt(serialize_response(response_data), self.cipher)
            elif isinstance(client_request, RevokeRequest):
                response = revoke_file_access(client_request, self.id)
                if response is None:
                    return encrypt(serialize_response(VaultError("Error revoking access")), self.cipher)
                return encrypt(serialize_response(RevokeResponse("Target id access revoked")), self.cipher)
            elif isinstance(client_request, GroupMembersRequest):
                members = get_group_members(client_request.group_id)
                return encrypt(serialize_response(GroupMembersResponse(members)), self.cipher)

            elif isinstance(client_request, PublicKeyRequest):
                public_key = get_public_key(client_request.user_id)
                if public_key:
                    response_data = PublicKeyResponse(public_key)
                    log_request(f"{self.id}", "public_key", [client_request.user_id], "success")
                else:
                    response_data = VaultError("User not found")
                    log_request(f"{self.id}", "public_key", [client_request.user_id], "failed", "public key not found")

                return encrypt(serialize_response(response_data), self.cipher)
            elif isinstance(client_request, ShareRequest):
                file_info = get_file_by_id(client_request.fileid)

                if not file_info:
                    log_request(f"{self.id}", "share", [client_request.fileid], "failed", "file not found")
                    response_data = VaultError("File not found.")
                    return encrypt(serialize_response(response_data), self.cipher)

                error_message = share_file(file_info, client_request, self.id)

                if error_message:
                    log_request(f"{self.id}", "share", [client_request.fileid], "failed", error_message)
                    response_data = VaultError(error_message)
                    return encrypt(serialize_response(response_data), self.cipher)

                log_request(f"{self.id}", "share", [client_request.fileid], "success")
                if client_request.is_group:
                    members = get_group_members(client_request.target_id)
                    for member in members:
                        if member["userid"] != self.id:
                            add_notification(member["userid"], f"User {self.id} shared file {client_request.fileid} to your group {client_request.target_id}.")
                else:
                    add_notification(client_request.target_id , f"User {self.id} shared file {client_request.fileid}.")
                response_data = ShareResponse("File shared successfully.")
                return encrypt(serialize_response(response_data), self.cipher)
            elif (isinstance(client_request, GroupCreateRequest)):
                group_name = client_request.group_name

                group_id = add_group_request(group_name, self.id)

                response_data = GroupCreateResponse(f"group {group_id} created.")
                return encrypt(serialize_response(response_data), self.cipher)
            elif isinstance(client_request, GroupDeleteRequest):
                group_id = client_request.group_id
                error_message = group_delete(group_id, self.id)

                if error_message:
                    log_request(f"{self.id}", "group delete", [group_id], "failed", error_message)
                    response_data = VaultError(error_message)
                    return encrypt(serialize_response(response_data), self.cipher)

                log_request(f"{self.id}", "group delete", [group_id], "success")
                response_data = GroupDeleteResponse(f"Group {group_id} deleted.")
                return encrypt(serialize_response(response_data), self.cipher)
            elif isinstance(client_request, GroupAddUserRequest):
                group_id = client_request.group_id
                user_id = client_request.user_id
                permission = client_request.permission
                encrypted_keys = client_request.encrypted_keys

                error_message = add_user_to_group(self.id, group_id, user_id, permission, encrypted_keys)

                if error_message:
                    log_request(f"{self.id}", "group add user", [group_id, user_id], "failed", error_message)
                    response_data = VaultError(error_message)
                    return encrypt(serialize_response(response_data), self.cipher)

                log_request(f"{self.id}", "group add user", [group_id, user_id], "success")
                add_notification(user_id, f"User {self.id} added you to group {group_id}.")
                response_data = GroupAddUserResponse(f"User {user_id} added to group {group_id}.")
                return encrypt(serialize_response(response_data), self.cipher)
            elif isinstance(client_request, GroupAddUserRequirementsRequest):
                group_id = client_request.group_id
                user_id = client_request.user_id

                requirements = add_user_to_group_requirements(self.id, group_id)
                if "error" in requirements:
                    log_request(self.id, "group add user requirements", [group_id, user_id], "failed", requirements["error"])
                    return encrypt(serialize_response(VaultError(requirements["error"])), self.cipher)

                public_key = get_public_key(user_id)

                if not public_key:
                    log_request(self.id, "group add user requirements", [group_id, user_id], "failed", "Target user not found")
                    return encrypt(serialize_response(VaultError("Target user not found")), self.cipher)

                response_data = GroupAddUserRequirementsResponse(
                    encrypted_keys=requirements,
                    public_key=public_key
                )

                log_request(self.id, "group add user requirements", [group_id, user_id], "success")
                return encrypt(serialize_response(response_data), self.cipher)
            elif isinstance(client_request, GroupListRequest):
                groups = get_user_permissions_by_group(self.id)

                response_data = GroupListResponse(groups)
                log_request(f"{self.id}", "group list", [], "success")
                return encrypt(serialize_response(response_data), self.cipher)
            elif isinstance(client_request, GroupPublicKeysRequest):
                group_id = client_request.group_id
                public_keys = get_group_public_keys(group_id, self.id)

                if public_keys == []:
                    log_request(f"{self.id}", "group public keys", [group_id], "failed", "public key not found or no write permission")
                    response_data = VaultError("Invalid operation.")
                    return encrypt(serialize_response(response_data), self.cipher)

                response_data = GroupPublicKeysResponse(public_keys)
                log_request(f"{self.id}", "group public keys", [group_id], "success")
                return encrypt(serialize_response(response_data), self.cipher)
            elif isinstance(client_request, GroupAddRequest):
                file_id = group_add_request(client_request, self.id)

                if file_id is None:
                    log_request(f"{self.id}", "group add", [client_request.file_id], "failed", "file not found")
                    response_data = VaultError("Invalid operation.")
                    return encrypt(serialize_response(response_data), self.cipher)

                response_data = GroupAddResponse(f"File added to group successfully with id {file_id}.")
                return encrypt(serialize_response(response_data), self.cipher)
            else:
                return encrypt(VaultError("Error: Unknown request type.").encode(), self.cipher)
        except Exception as e:
            return encrypt(serialize_response(VaultError(f"Error: {str(e)}")), self.cipher)

# Client/Server functionality
async def handle_echo(reader: StreamReader, writer: StreamWriter) -> None:
    global conn_cnt
    conn_cnt += 1
    addr = writer.get_extra_info("peername")
    srvwrk = ServerWorker(conn_cnt, addr)

    await srvwrk.handshake(reader, writer)
    if srvwrk.cipher is None:
        writer.close()
        return

    await srvwrk.send_notifications(writer)

    data = await reader.read(max_msg_size)
    while True:
        if not data:
            continue

        if data[:1] == b"\n":
            break

        data = srvwrk.process(data)

        if not data:
            break

        writer.write(data)
        await writer.drain()
        data = await reader.read(max_msg_size)
    print("[%s]" % srvwrk.id)
    writer.close()


def run_server() -> None:
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_echo, "127.0.0.1", conn_port)
    server = loop.run_until_complete(coro)
    # Serve requests until Ctrl+C is pressed
    print("Serving on {}".format(server.sockets[0].getsockname()))
    print("  (type ^C to finish)\n")
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print("\nFINISHED!")


run_server()
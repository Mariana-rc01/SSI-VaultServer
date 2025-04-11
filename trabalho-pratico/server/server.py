import asyncio
import os
import json
import base64
from typing import Optional, Tuple, Union
from asyncio.streams import StreamReader, StreamWriter

from utils.utils import (
    encrypt,
    decrypt,
    is_signature_valid,
    deserialize_public_key,
    is_certificate_valid,
    generate_private_key,
    generate_public_key,
    serialize_public_key,
    sign_message_with_rsa,
    serialize_certificate,
    generate_shared_key,
    generate_derived_key,
    build_aesgcm,
    certificate_create,
)
from server.utils import log_request, get_file_by_id, add_request, add_user
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates

conn_cnt = 0
conn_port = 7777
max_msg_size = 9999

STORAGE_DIR = "./storage"
os.makedirs(STORAGE_DIR, exist_ok=True)
DB_DIR = "./db"
os.makedirs(DB_DIR, exist_ok=True)


class ServerWorker:
    """Class that implements the functionality of the SERVER."""

    def __init__(self, cnt: int, addr: Optional[Tuple[str, int]] = None) -> None:
        """Class constructor."""
        self.id: int = cnt
        self.addr: Optional[Tuple[str, int]] = addr
        self.msg_cnt: int = 0
        self.aesgcm = None

    async def handshake(self, reader: StreamReader, writer: StreamWriter) -> None:
        with open("./certificates/VAULT_SERVER.p12", "rb") as p12_file:
            p12_data = p12_file.read()
        rsa_private_key, server_certificate, _ = load_key_and_certificates(p12_data, None)

        # Receive client's public key
        request = await reader.read(max_msg_size)
        request_data = json.loads(request.decode())
        serialized_client_public_key = base64.b64decode(request_data["public_key"])
        client_public_key = deserialize_public_key(serialized_client_public_key)

        # Generate server's public key and signature
        dh_private_key = generate_private_key()
        dh_public_key = generate_public_key(dh_private_key)
        serialized_public_key = serialize_public_key(dh_public_key)

        both_public_keys = serialized_client_public_key + serialized_public_key
        signature = sign_message_with_rsa(both_public_keys, rsa_private_key)
        serialized_certificate = serialize_certificate(server_certificate)

        # Send server's public key, certificate, and signature
        writer.write(
            json.dumps(
                {
                    "public_key": base64.b64encode(serialized_public_key).decode(),
                    "certificate": base64.b64encode(serialized_certificate).decode(),
                    "signature": base64.b64encode(signature).decode(),
                }
            ).encode()
        )
        await writer.drain()

        # Receive client's certificate and signature
        response = await reader.read(max_msg_size)
        response_data = json.loads(response.decode())
        client_signature = base64.b64decode(response_data["signature"])
        client_certificate = certificate_create(base64.b64decode(response_data["certificate"]))
        client_subject = base64.b64decode(response_data["subject"]).decode()

        # Validate certificate
        certificate_valid = is_certificate_valid(client_certificate, client_subject)
        if not certificate_valid:
            # Abort connection
            print("Aborting handshake...")
            return

        # Extract client's public key from certificate
        client_certificate_public_key = client_certificate.public_key()

        # Validate signature
        signature_valid = is_signature_valid(client_signature, both_public_keys, client_certificate_public_key)
        if not signature_valid:
            # Abort connection
            print("Aborting handshake...")
            return

        self.id = add_user(client_subject, client_certificate_public_key)

        # Derived shared key
        shared_key = generate_shared_key(dh_private_key, client_public_key)
        derived_key = generate_derived_key(shared_key)
        self.aesgcm = build_aesgcm(derived_key)

    def process(self, msg: bytes) -> Optional[bytes]:
        """Processes a message (`bytestring`) sent by the CLIENT.
        Returns the message to be sent as a response (`None` to
        terminate the connection)."""
        self.msg_cnt += 1
        plaintext = decrypt(msg, self.aesgcm)

        try:
            client_request = json.loads(plaintext.decode("utf-8"))
            request_type = client_request.get("type")
            request_args = client_request.get("args")

            if request_type == "add":
                filename = request_args[0]
                filedata_b64 = request_args[1]
                filedata = base64.b64decode(filedata_b64)

                file_id = add_request(filename, filedata, self.id)

                return encrypt(f"File saved with id: {file_id}".encode(), self.aesgcm)
            elif request_type == "read":
                file_id = request_args[0]

                file_info = get_file_by_id(file_id)

                if not file_info or not os.path.exists(file_info["location"]):
                    log_request(f"{self.id}", "read", [file_id], "failed", "file not found")
                    return encrypt(f"Error: file {file_id} not found.".encode(), self.aesgcm)

                with open(file_info["location"], "rb") as f:
                    filedata = f.read()
                log_request(f"{self.id}", "read", [file_id], "success")

                return encrypt(filedata, self.aesgcm)
            else:
                return encrypt(b"Invalid command", self.aesgcm)
        except Exception as e:
            return encrypt(f"Erro: {str(e)}".encode(), self.aesgcm)


# Client/Server functionality
async def handle_echo(reader: StreamReader, writer: StreamWriter) -> None:
    global conn_cnt
    conn_cnt += 1
    addr = writer.get_extra_info("peername")
    srvwrk = ServerWorker(conn_cnt, addr)

    await srvwrk.handshake(reader, writer)
    if srvwrk.aesgcm is None:
        writer.close()
        return

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

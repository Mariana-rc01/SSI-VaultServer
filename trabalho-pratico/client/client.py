import asyncio, json, base64, argparse

from utils.utils import generate_derived_key, generate_private_key, generate_public_key, serialize_public_key, deserialize_public_key, generate_shared_key, encrypt, decrypt, build_aesgcm, request, certificate_create, is_certificate_valid, is_signature_valid, sign_message_with_rsa, serialize_certificate
from client.utils import add, read
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from cryptography.x509.oid import NameOID

conn_port = 7777
max_msg_size = 9999

class Client:
    """ Class that implements the functionality of a CLIENT. """
    def __init__(self, sckt=None, rsa_private_key=None, client_certificate=None):
        """ Class constructor. """
        self.sckt = sckt
        self.msg_cnt = 0
        self.aesgcm = None
        self.last_cmd = None
        self.rsa_private_key = rsa_private_key
        self.client_certificate = client_certificate

    async def handshake(self, reader, writer):
        """ Performs the handshake with the server. """
        # Send public key to the server
        dh_private_key = generate_private_key()
        dh_public_key = generate_public_key(dh_private_key)
        serialized_public_key = serialize_public_key(dh_public_key)

        # Codificar a chave pública em Base64 antes de enviar
        serialized_public_key_json = json.dumps({
            "public_key": base64.b64encode(serialized_public_key).decode()
        }).encode()
        writer.write(serialized_public_key_json)
        await writer.drain()

        # Receive server's public key, certificate, and signature
        response = await reader.read(max_msg_size)
        response_data = json.loads(response.decode())
        serialized_server_public_key = base64.b64decode(response_data["public_key"])
        server_certificate = base64.b64decode(response_data["certificate"])
        server_signature = base64.b64decode(response_data["signature"])

        server_public_key = deserialize_public_key(serialized_server_public_key)
        server_certificate_obj = certificate_create(server_certificate)

        # Validate certificate
        certificate_valid = is_certificate_valid(server_certificate_obj, "SSI Vault Server")
        if not certificate_valid:
            # Abort connection
            print("Aborting handshake...")
            return

        # Extract server's public key from certificate
        server_certificate_public_key = server_certificate_obj.public_key()

        # Validate signature
        both_public_keys = serialized_public_key + serialized_server_public_key
        signature_valid = is_signature_valid(server_signature, both_public_keys, server_certificate_public_key)
        if not signature_valid:
            # Abort connection
            print("Aborting handshake...")
            return

        # Derived shared key
        shared_key = generate_shared_key(dh_private_key, server_public_key)
        derived_key = generate_derived_key(shared_key)
        self.aesgcm = build_aesgcm(derived_key)

        # Send client certificate and signature to the server
        client_signature = sign_message_with_rsa(both_public_keys, self.rsa_private_key)
        client_certificate_subject = self.client_certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        writer.write(json.dumps({
            "signature": base64.b64encode(client_signature).decode(),
            "certificate": base64.b64encode(serialize_certificate(self.client_certificate)).decode(),
            "subject": base64.b64encode(client_certificate_subject.encode()).decode()
        }).encode())
        await writer.drain()

        print('Handshake completed!')

    def process(self, msg=b""):
        """ Processes a message (`bytestring`) sent by the SERVER.
            Returns the message to be sent as a response (`None` to
            terminate the connection). """
        if len(msg) != 0:
            self.msg_cnt += 1
            decrypted_msg = decrypt(msg, self.aesgcm)

            if self.last_command == "read":
                read(decrypted_msg)
                self.last_command = None
            else:
                print('Received (%d): %r' % (self.msg_cnt, decrypted_msg.decode()))

        print('\nCommand [add <file-path> | read <file-id> | exit]:')
        new_msg = input().strip()
        if new_msg.startswith("add "):
            self.last_command = "add"
            file_path = new_msg.split(" ", 1)[1]

            json_bytes = add(file_path)
            if not json_bytes:
                return b""

            return encrypt(json_bytes, self.aesgcm)
        elif new_msg.startswith("read "):
            self.last_command = "read"
            file_id = new_msg.split(" ", 1)[1]

            read_request = request("read", [file_id])
            json_bytes = json.dumps(read_request).encode('utf-8')

            return encrypt(json_bytes, self.aesgcm)
        elif new_msg.strip() == "exit":
            return None
        else:
            print("Invalid command.")
            return b""

# Client/Server functionality
async def tcp_echo_client(args):
    """ Establishes the connection with the server and handles communication. """

    # Load the PKCS#12 file
    with open(args.p12_path, "rb") as p12_file:
        p12_data = p12_file.read()

    password = args.password.encode() if args.password else None
    private_key, certificate, _ = load_key_and_certificates(p12_data, password)

    reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
    addr = writer.get_extra_info('peername')
    client = Client(addr, rsa_private_key=private_key, client_certificate=certificate)

    await client.handshake(reader, writer)
    if client.aesgcm is None:
        return

    msg = client.process()
    while msg:
        writer.write(msg)
        msg = await reader.read(max_msg_size)
        if msg:
            msg = client.process(msg)
        else:
            break
    writer.write(b'\n')
    print('Socket closed!')
    writer.close()

def run_client():
    """ Runs the client event loop. """
    parser = argparse.ArgumentParser(description="Client for secure communication.")
    parser.add_argument("p12_path", help="Path to the PKCS#12 file (.p12)")
    parser.add_argument("--password", help="Password for the PKCS#12 file", default="")
    args = parser.parse_args()

    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client(args))

run_client()

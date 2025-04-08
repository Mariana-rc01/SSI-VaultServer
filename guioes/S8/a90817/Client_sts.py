import argparse
import asyncio
import utils, json
import base64  # Adicionado para codificação Base64
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from cryptography.x509.oid import NameOID

conn_port = 7777
max_msg_size = 9999

class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, sckt=None, rsa_private_key=None, client_certificate=None):
        """ Construtor da classe. """
        self.sckt = sckt
        self.msg_cnt = 0
        self.aesgcm = None
        self.rsa_private_key = rsa_private_key
        self.client_certificate = client_certificate

    async def handshake(self, reader, writer):
        # Send public key to the server
        dh_private_key = utils.generate_private_key()
        dh_public_key = utils.generate_public_key(dh_private_key)
        serialized_public_key = utils.serialize_public_key(dh_public_key)

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

        server_public_key = utils.deserialize_public_key(serialized_server_public_key)
        server_certificate_obj = utils.certificate_create(server_certificate)

        # Validate certificate
        is_certificate_valid = utils.is_certificate_valid(server_certificate_obj, "SSI Vault Server")
        if not is_certificate_valid:
            # Abort connection
            print("Aborting handshake...")
            return

        # Extract server's public key from certificate
        server_certificate_public_key = server_certificate_obj.public_key()

        # Validate signature
        both_public_keys = serialized_public_key + serialized_server_public_key
        is_signature_valid = utils.is_signature_valid(server_signature, both_public_keys, server_certificate_public_key)
        if not is_signature_valid:
            # Abort connection
            print("Aborting handshake...")
            return

        # Derived shared key
        shared_key = utils.generate_shared_key(dh_private_key, server_public_key)
        derived_key = utils.generate_derived_key(shared_key)
        self.aesgcm = utils.build_aesgcm(derived_key)

        # Send client certificate and signature to the server
        client_signature = utils.sign_message_with_rsa(both_public_keys, self.rsa_private_key)
        client_certificate_subject = self.client_certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        writer.write(json.dumps({
            "signature": base64.b64encode(client_signature).decode(),
            "certificate": base64.b64encode(utils.serialize_certificate(self.client_certificate)).decode(),
            "subject": base64.b64encode(client_certificate_subject.encode()).decode()  # Corrigido aqui
        }).encode())
        await writer.drain()

        print('Handshake completed!')

    def process(self, msg=b""):
        """ Processa uma mensagem (`bytestring`) enviada pelo SERVIDOR.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        if len(msg) != 0:
            self.msg_cnt += 1
            msg = utils.decrypt(msg, self.aesgcm)
            print('Received (%d): %r' % (self.msg_cnt, msg.decode()))

        print('Input message to send (empty to finish)')
        new_msg = input().encode()

        if len(new_msg) > 0:
            new_msg = utils.encrypt(new_msg, self.aesgcm)
        return new_msg if len(new_msg) > 0 else None

# Funcionalidade Cliente/Servidor
async def tcp_echo_client(args):
    # Load the PKCS#12 file
    with open(args.p12_path, "rb") as p12_file:
        p12_data = p12_file.read()

    password = args.password.encode() if args.password else None
    private_key, certificate, _ = load_key_and_certificates(p12_data, password)

    # Create the client
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
    parser = argparse.ArgumentParser(description="Client for secure communication.")
    parser.add_argument("p12_path", help="Path to the PKCS#12 file (.p12)")
    parser.add_argument("--password", help="Password for the PKCS#12 file", default="")
    args = parser.parse_args()

    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client(args))


run_client()
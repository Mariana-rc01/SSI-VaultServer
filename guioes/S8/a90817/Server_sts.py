# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import utils, json
import base64  # Adicionado para codificação Base64
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates

conn_cnt = 0
conn_port = 7777
max_msg_size = 9999

class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, addr=None):
        """ Construtor da classe. """
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.aesgcm = None

    async def handshake(self, reader, writer):
        with open("./certificates/VAULT_SERVER.p12", "rb") as p12_file:
            p12_data = p12_file.read()
        rsa_private_key, server_certificate, _ = load_key_and_certificates(p12_data, None)

        # Receive client's public key
        request = await reader.read(max_msg_size)
        request_data = json.loads(request.decode())
        serialized_client_public_key = base64.b64decode(request_data["public_key"])
        client_public_key = utils.deserialize_public_key(serialized_client_public_key)

        # Generate server's public key and signature
        dh_private_key = utils.generate_private_key()
        dh_public_key = utils.generate_public_key(dh_private_key)
        serialized_public_key = utils.serialize_public_key(dh_public_key)

        both_public_keys = serialized_client_public_key + serialized_public_key
        signature = utils.sign_message_with_rsa(both_public_keys, rsa_private_key)
        serialized_certificate = utils.serialize_certificate(server_certificate)

        # Send server's public key, certificate, and signature
        writer.write(json.dumps({
            "public_key": base64.b64encode(serialized_public_key).decode(),
            "certificate": base64.b64encode(serialized_certificate).decode(),
            "signature": base64.b64encode(signature).decode()
        }).encode())
        await writer.drain()

        # Receive client's certificate and signature
        response = await reader.read(max_msg_size)
        response_data = json.loads(response.decode())
        client_signature = base64.b64decode(response_data["signature"])
        client_certificate = utils.certificate_create(base64.b64decode(response_data["certificate"]))
        client_subject = base64.b64decode(response_data["subject"])

        # Validate certificate
        is_certificate_valid = utils.is_certificate_valid(client_certificate, client_subject.decode())
        if not is_certificate_valid:
            # Abort connection
            print("Aborting handshake...")
            return

        # Extract client's public key from certificate
        client_certificate_public_key = client_certificate.public_key()

        # Validate signature
        is_signature_valid = utils.is_signature_valid(client_signature, both_public_keys, client_certificate_public_key)
        if not is_signature_valid:
            # Abort connection
            print("Aborting handshake...")
            return

        # Derived shared key
        shared_key = utils.generate_shared_key(dh_private_key, client_public_key)
        derived_key = utils.generate_derived_key(shared_key)
        self.aesgcm = utils.build_aesgcm(derived_key)

    def process(self, msg):
        """ Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt += 1
        msg = utils.decrypt(msg, self.aesgcm)
        print('%d : %r' % (self.id, msg.decode()))
        new_msg = msg.decode().upper().encode()
        if len(new_msg) > 0:
            new_msg = utils.encrypt(new_msg, self.aesgcm)
        return new_msg if len(new_msg)>0 else None

# Funcionalidade Cliente/Servidor
async def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt +=1
    addr = writer.get_extra_info('peername')
    srvwrk = ServerWorker(conn_cnt, addr)

    await srvwrk.handshake(reader, writer)
    if srvwrk.aesgcm is None:
        writer.close()
        return

    data = await reader.read(max_msg_size)
    while True:
        if not data: continue

        if data[:1]==b'\n': break

        data = srvwrk.process(data)

        if not data: break

        writer.write(data)
        await writer.drain()
        data = await reader.read(max_msg_size)
    print("[%d]" % srvwrk.id)
    writer.close()


def run_server():
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_echo, '127.0.0.1', conn_port)
    server = loop.run_until_complete(coro)
    # Serve requests until Ctrl+C is pressed
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    print('  (type ^C to finish)\n')
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print('\nFINISHED!')

run_server()
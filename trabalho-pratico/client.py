import asyncio
import utils

conn_port = 7777
max_msg_size = 9999

class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, sckt=None):
        """ Construtor da classe. """
        self.sckt = sckt
        self.msg_cnt = 0
        self.aesgcm = None
    async def handshake(self, reader, writer) :
        private_key = utils.generate_private_key()
        public_key = utils.generate_public_key(private_key)
        serialized_public_key = utils.serialize_public_key(public_key)
        writer.write(serialized_public_key)
        await writer.drain()

        serialized_server_public_key = await reader.read(max_msg_size)
        server_public_key = utils.deserialize_public_key(serialized_server_public_key)

        shared_key = utils.generate_shared_key(private_key, server_public_key)
        derived_key = utils.generate_derived_key(shared_key)
        self.aesgcm = utils.build_aesgcm(derived_key)

    def process(self, msg=b""):
        """ Processa uma mensagem (`bytestring`) enviada pelo SERVIDOR.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        if len(msg) != 0:
            self.msg_cnt +=1
            msg = utils.decrypt(msg, self.aesgcm)
            print('Received (%d): %r' % (self.msg_cnt , msg.decode()))

        print('Input message to send (empty to finish)')
        new_msg = input().encode()

        if len(new_msg) > 0:
            new_msg = utils.encrypt(new_msg, self.aesgcm)
        return new_msg if len(new_msg)>0 else None

# Funcionalidade Cliente/Servidor
async def tcp_echo_client():
    reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
    addr = writer.get_extra_info('peername')
    client = Client(addr)

    await client.handshake(reader,writer)
    if client.aesgcm is None: return

    msg = client.process()
    while msg:
        writer.write(msg)
        msg = await reader.read(max_msg_size)
        if msg :
            msg = client.process(msg)
        else:
            break
    writer.write(b'\n')
    print('Socket closed!')
    writer.close()

def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())


run_client()
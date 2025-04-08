# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import utils

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

    async def handshake(self, reader, writer) :
        private_key = utils.generate_private_key()
        public_key = utils.generate_public_key(private_key)
        serialized_public_key = utils.serialize_public_key(public_key)
        writer.write(serialized_public_key)
        await writer.drain()

        serialized_client_public_key = await reader.read(max_msg_size)
        client_public_key = utils.deserialize_public_key(serialized_client_public_key)

        shared_key = utils.generate_shared_key(private_key, client_public_key)
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
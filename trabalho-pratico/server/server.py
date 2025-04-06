import asyncio
import os, json, base64
from datetime import datetime

from utils.utils import generate_derived_key, generate_private_key, generate_public_key, serialize_public_key, deserialize_public_key, generate_shared_key, encrypt, decrypt, build_aesgcm
from server.utils import log_request, get_file_by_id, add_request

conn_cnt = 0
conn_port = 7777
max_msg_size = 9999

STORAGE_DIR = "./storage"
os.makedirs(STORAGE_DIR, exist_ok=True)

class ServerWorker(object):
    """ Class that implements the functionality of the SERVER. """
    def __init__(self, cnt, addr=None):
        """ Class constructor. """
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.aesgcm = None

    async def handshake(self, reader, writer) :
        private_key = generate_private_key()
        public_key = generate_public_key(private_key)
        serialized_public_key = serialize_public_key(public_key)
        writer.write(serialized_public_key)
        await writer.drain()

        serialized_client_public_key = await reader.read(max_msg_size)
        client_public_key = deserialize_public_key(serialized_client_public_key)

        shared_key = generate_shared_key(private_key, client_public_key)
        derived_key = generate_derived_key(shared_key)
        self.aesgcm = build_aesgcm(derived_key)

    def process(self, msg):
        """ Processes a message (`bytestring`) sent by the CLIENT.
            Returns the message to be sent as a response (`None` to
            terminate the connection). """
        self.msg_cnt += 1
        plaintext = decrypt(msg, self.aesgcm)

        try:
            client_request = json.loads(plaintext.decode('utf-8'))
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
                    log_request(f"u{self.id}", "read", [file_id], "failed", "file not found")
                    return encrypt(f"Error: file {file_id} not found.".encode(), self.aesgcm)

                with open(file_info["location"], "rb") as f:
                    filedata = f.read()
                log_request(f"u{self.id}", "read", [file_id], "success")

                return encrypt(filedata, self.aesgcm)
            else:
                return encrypt(b"Invalid command", self.aesgcm)
        except Exception as e:
            return encrypt(f"Erro: {str(e)}".encode(), self.aesgcm)

# Client/Server functionality
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

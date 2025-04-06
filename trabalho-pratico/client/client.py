import asyncio, json

from utils.utils import generate_derived_key, generate_private_key, generate_public_key, serialize_public_key, deserialize_public_key, generate_shared_key, encrypt, decrypt, build_aesgcm, request
from client.utils import add, read

conn_port = 7777
max_msg_size = 9999

class Client:
    """ Class that implements the functionality of a CLIENT. """
    def __init__(self, sckt=None):
        """ Class constructor. """
        self.sckt = sckt
        self.msg_cnt = 0
        self.aesgcm = None
        self.last_cmd = None

    async def handshake(self, reader, writer):
        """ Performs the handshake with the server. """
        private_key = generate_private_key()
        public_key = generate_public_key(private_key)
        serialized_public_key = serialize_public_key(public_key)
        writer.write(serialized_public_key)
        await writer.drain()

        serialized_server_public_key = await reader.read(max_msg_size)
        server_public_key = deserialize_public_key(serialized_server_public_key)

        shared_key = generate_shared_key(private_key, server_public_key)
        derived_key = generate_derived_key(shared_key)
        self.aesgcm = build_aesgcm(derived_key)

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
async def tcp_echo_client():
    """ Establishes the connection with the server and handles communication. """
    reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
    addr = writer.get_extra_info('peername')
    client = Client(addr)

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
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())

run_client()

# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import socket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

conn_port = 7777
max_msg_size = 9999

key = b'0123456789abcdef0123456789abcdef'

class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, sckt=None):
        """ Construtor da classe. """
        self.sckt = sckt
        self.msg_cnt = 0
    def process(self, msg=b""):
        """ Processa uma mensagem (`bytestring`) enviada pelo SERVIDOR.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt += 1
        
        aesgcm = AESGCM(key)

        if msg:
            try:
                nonce, ciphertext = msg[:12], msg[12:]
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                print('Received (%d): %r' % (self.msg_cnt, plaintext.decode()))
            except Exception as e:
                print("Error decrypting:", e)
                return None

        print('Input message to send (empty to finish)')
        new_msg = input().encode()

        if len(new_msg) > 0:
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, new_msg, None)
            return nonce + ciphertext
        else:
            return None



#
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#


async def tcp_echo_client():
    reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
    addr = writer.get_extra_info('peername')
    client = Client(addr)
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
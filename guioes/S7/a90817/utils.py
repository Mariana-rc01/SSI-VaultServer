import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2

def generate_private_key():
    parameters = dh.DHParameterNumbers(p,g).parameters()
    return parameters.generate_private_key()

def generate_public_key(private_key):
    return private_key.public_key()

def generate_shared_key(private_key, public_key):
    return private_key.exchange(public_key)

def generate_derived_key(shared_key):
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    return derived_key

def serialize_public_key(public_key: dh.DHPublicKey):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem

def deserialize_public_key(serialized_public_key):
    return serialization.load_pem_public_key(serialized_public_key, default_backend())

def encrypt(content, aesgcm: AESGCM):
    nonce = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce, content, None)
    return nonce+encrypted

def decrypt(content, aesgcm: AESGCM):
    nonce = content[:12]
    real_content = content[12:]
    ct = aesgcm.decrypt(nonce, real_content, None)
    return ct

def build_aesgcm(key):
    return AESGCM(key)
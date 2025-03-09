import sys, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_key():
    return os.urandom(32)

def save_file(key, fkey):
    file = open(fkey, "wb")
    file.write(key)
    file.close()

def load_key(fkey):
    file = open(fkey, "rb")
    key = file.read()
    file.close()
    return key

def encrypt_file(fich, fkey):
    key = load_key(fkey)
    nonce = os.urandom(16)
    
    with open(fich, 'rb') as f:
        plaintext = f.read()
    
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)

    print(len(ciphertext))
    print(len(nonce))
    
    enc_fich = fich + ".enc"
    with open(enc_fich, 'wb') as f:
        f.write(nonce + ciphertext)
    
def decrypt_file(fich, fkey):
    key = load_key(fkey)
    
    with open(fich, 'rb') as f:
        nonce = f.read(16)
        ciphertext = f.read()
    
    print(len(nonce))
    print(len(ciphertext))

    #nonce = data[:16]
    #ciphertext = data[16:]
    
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext)
    
    dec_fich = fich + ".dec"
    with open(dec_fich, 'wb') as f:
        f.write(plaintext)
    
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python cfich_chacha20.py <setup|enc|dec> <fich> [fkey]")
        sys.exit(1)
    
    operation = sys.argv[1]
    if operation == "setup":
        fkey = sys.argv[2]
        key = generate_key()
        save_file(key, fkey)
    elif operation == "enc":
        if len(sys.argv) < 4:
            print("Erro: Necessário fornecer ficheiro e chave.")
            sys.exit(1)
        fich, fkey = sys.argv[2], sys.argv[3]
        encrypt_file(fich, fkey)
    elif operation == "dec":
        if len(sys.argv) < 4:
            print("Erro: Necessário fornecer ficheiro e chave.")
            sys.exit(1)
        fich, fkey = sys.argv[2], sys.argv[3]
        decrypt_file(fich, fkey)
    else:
        print("Operação inválida. Usa setup, enc ou dec.")
        sys.exit(1)

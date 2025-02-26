import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

def generate_key():
    return os.urandom(32)

def save_key(key, filename):
    with open(filename, 'wb') as f:
        f.write(key)

def load_key(filename):
    with open(filename, 'rb') as f:
        return f.read()

def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)
    
    with open(file_path + '.enc', 'wb') as f:
        f.write(nonce + ciphertext)

def decrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        nonce = f.read(16)
        ciphertext = f.read()
    
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext)
    
    with open(file_path + '.dec', 'wb') as f:
        f.write(plaintext)

def main():
    if len(sys.argv) < 3:
        print("Usage: cfich_chacha20.py <operation> <arguments>")
        sys.exit(1)
    
    operation = sys.argv[1]
    
    if operation == 'setup':
        if len(sys.argv) != 3:
            print("Usage: cfich_chacha20.py setup <fkey>")
            sys.exit(1)
        key = generate_key()
        save_key(key, sys.argv[2])
    elif operation == 'enc':
        if len(sys.argv) != 4:
            print("Usage: cfich_chacha20.py enc <fich> <fkey>")
            sys.exit(1)
        key = load_key(sys.argv[3])
        encrypt_file(sys.argv[2], key)
    elif operation == 'dec':
        if len(sys.argv) != 4:
            print("Usage: cfich_chacha20.py dec <fich> <fkey>")
            sys.exit(1)
        key = load_key(sys.argv[3])
        decrypt_file(sys.argv[2], key)
    else:
        print("Invalid operation. Use 'setup', 'enc', or 'dec'.")
        sys.exit(1)

if __name__ == "__main__":
    main()

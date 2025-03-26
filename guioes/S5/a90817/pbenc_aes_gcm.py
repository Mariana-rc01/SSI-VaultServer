import sys, os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_keys(passphrase, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    keyG = kdf.derive(passphrase)

    return keyG

def encrypt(fToEncrypted):
    with open(fToEncrypted, 'rb') as f:
        text = f.read()

    passphrase = input("Digite uma passphrase: ").encode()
    aad = input("Destination: ").encode()
    salt = os.urandom(16)
    key = generate_keys(passphrase, salt)

    nonce = os.urandom(12)
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, text, aad)

    encrypted_file = fToEncrypted + '.enc'
    with open(encrypted_file, 'wb') as f:
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)

def decrypt(fToDecrypted):
    with open(fToDecrypted, 'rb') as f:
        salt = f.read(16)
        nonce = f.read(12)
        ct = f.read()

    passphrase = input("Digite a passphrase: ").encode()
    aad = input("Destination: ").encode()
    key = generate_keys(passphrase, salt)

    cipher = AESGCM(key)
    plaintext = cipher.decrypt(nonce, ct, aad)

    decrypted_file = fToDecrypted.replace('.enc', '.dec')
    with open(decrypted_file, 'wb') as f:
        f.write(plaintext)

def main(args):
    if len(args) < 3:
        print("Uso: python script.py [enc|dec] <arquivo>")
        return

    operation, file_path = args[1], args[2]

    if operation == 'enc':
        encrypt(file_path)
    elif operation == 'dec':
        decrypt(file_path)
    else:
        print("Not valid.")

if __name__ == "__main__":
    main(sys.argv)

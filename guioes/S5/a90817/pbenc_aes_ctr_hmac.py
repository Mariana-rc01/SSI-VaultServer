import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_keys(passphrase, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=480000,
    )
    keyG = kdf.derive(passphrase)

    aes_key = keyG[:32]
    hmac_key = keyG[32:]

    return aes_key, hmac_key

def generate_hmac(hmac_key, ct):
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(ct)
    return h.finalize()

def verify_hmac(hmac_key, ct, stored_hmac):
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(ct)
    try:
        h.verify(stored_hmac)
        return True
    except InvalidSignature:
        return False

def encrypt(fToEncrypted):
    with open(fToEncrypted, 'rb') as f:
        text = f.read()

    passphrase = input("Digite uma passphrase: ").encode()
    salt = os.urandom(16)
    aes_key, hmac_key = generate_keys(passphrase, salt)

    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(text) + encryptor.finalize()

    hmac_signature = generate_hmac(hmac_key, ciphertext)

    encrypted_file = fToEncrypted + '.enc'
    with open(encrypted_file, 'wb') as f:
        f.write(salt)
        f.write(nonce)
        f.write(hmac_signature)
        f.write(ciphertext)

def decrypt(fToDecrypted):
    with open(fToDecrypted, 'rb') as f:
        salt = f.read(16)
        nonce = f.read(16)
        stored_hmac = f.read(32)
        ct = f.read()

    passphrase = input("Digite a passphrase: ").encode()
    aes_key, hmac_key = generate_keys(passphrase, salt)

    if not verify_hmac(hmac_key, ct, stored_hmac):
        print("Error")
        return

    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ct) + decryptor.finalize()

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
        print("Erro: Operação inválida. Use 'enc' para criptografar ou 'dec' para descriptografar.")

if __name__ == "__main__":
    main(sys.argv)

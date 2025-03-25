import sys, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generateKey(key, salt):
    kdf = PBKDF2HMAC(
        algorithm= hashes.SHA256(),
        length= 32,
        salt= salt,
        iterations= 480000,
    )
    keyGenerated = kdf.derive(key)
    return keyGenerated

def encrypt(fToEncrypted):
    with open(fToEncrypted, 'rb') as f:
        text = f.read()

    passphrase = input("Enter a passphrase: ").encode()
    salt = os.urandom(16)
    keyB = generateKey(passphrase, salt)

    nonce = os.urandom(12)

    aesgcm = AESGCM(keyB)
    ct = aesgcm.encrypt(nonce, text, None)

    with open(fToEncrypted + '.enc', 'wb') as f:
        f.write(salt)
        f.write(nonce)
        f.write(ct)

def decrypt(fToDecrypted):
    with open(fToDecrypted, 'rb') as f:
        salt = f.read(16)
        nonce = f.read(12)
        text = f.read()

    passphrase = input("Enter a passphrase: ").encode()
    keyB = generateKey(passphrase, salt)

    aesgcm = AESGCM(keyB)
    ct = aesgcm.decrypt(nonce, text, None)

    with open(fToDecrypted + '.dec', 'wb') as f:
        f.write(ct)

def main(args):
    if len(args) < 3:
        print("Error.")
        return
    operation = args[1]
    if (operation == 'enc'):
        file = args[2]
        encrypt(file)
    elif (operation == 'dec'):
        file = args[2]
        decrypt(file)
    else:
        print("Error.")

if __name__ == "__main__":
    main(sys.argv)

import sys, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def generateBytes(nBytes, filenameBytes):
    bytes = os.urandom(nBytes)
    with open(filenameBytes, 'wb') as f:
        f.write(bytes)

def encrypt(fToEncrypted, fKey):
    with open(fToEncrypted, 'rb') as f:
        text = f.read()

    with open(fKey, 'rb') as f:
        keyB = f.read()

    algorithm = algorithms.AES(keyB)
    nonce = os.urandom(16)
    mode = modes.CTR(nonce)
    cipher = Cipher(algorithm, mode)
    encryptor = cipher.encryptor()

    ct = encryptor.update(text)

    with open(fToEncrypted + '.enc', 'wb') as f:
        f.write(nonce)
        f.write(ct)

def decrypt(fToDecrypted, fKey):
    with open(fToDecrypted, 'rb') as f:
        nonce = f.read(16)
        text = f.read()
    with open(fKey, 'rb') as f:
        keyB = f.read()

    algorithm = algorithms.AES(keyB)
    mode = modes.CTR(nonce)
    cipher = Cipher(algorithm, mode)
    decryptor = cipher.decryptor()

    ct = decryptor.update(text)

    with open(fToDecrypted + '.dec', 'wb') as f:
        f.write(ct)

def main(args):
    if len(args) < 3:
        print("Error.")
        return
    operation = args[1]
    if (operation == 'setup'):
        fKey = args[2]
        generateBytes(32, fKey)
    elif (operation == 'enc'):
        file = args[2]
        fKey = args[3]
        encrypt(file, fKey)
    elif (operation == 'dec'):
        file = args[2]
        fKey = args[3]
        decrypt(file, fKey)
    else:
        print("Error.")

if __name__ == "__main__":
    main(sys.argv)

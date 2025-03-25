import sys, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac

def generateKey(key, salt):
    kdf = PBKDF2HMAC(
        algorithm= hashes.SHA256(),
        length= 64,
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
    keyAES = keyB[:32]
    keyHMAC = keyB[32:]

    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(keyAES), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ct = encryptor.update(text)

    h = hmac.HMAC(keyHMAC, hashes.SHA256())
    h.update(ct)
    signature = h.finalize()

    with open(fToEncrypted + '.enc', 'wb') as f:
        f.write(salt)
        f.write(nonce)
        f.write(signature)
        f.write(ct)

def decrypt(fToDecrypted):
    with open(fToDecrypted, 'rb') as f:
        salt = f.read(16)
        nonce = f.read(16)
        signature = f.read(32)
        text = f.read()

    passphrase = input("Enter a passphrase: ").encode()
    keyB = generateKey(passphrase, salt)

    keyAES = keyB[:32]
    keyHMAC = keyB[32:]

    h = hmac.HMAC(keyHMAC, hashes.SHA256())
    h.update(text)
    try:
        h.verify(signature)
    except:
        print("Error: Hmac verification")
        return

    cipher = Cipher(algorithms.AES(keyAES), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    ct = decryptor.update(text)

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

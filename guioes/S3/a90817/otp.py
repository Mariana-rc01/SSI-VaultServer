import sys
import os
import string

def cesar(operation, key, char):
    alphabet = string.ascii_uppercase
    if char.upper() in alphabet:
        idx = alphabet.index(char.upper())
        new_idx = (idx + operation * key) % 26
        return alphabet[new_idx] if char.isupper() else alphabet[new_idx].lower()
    return char

def vigenere(operation, key, text):
    crypted = []
    j = 0
    for char in text:
        key_value = ord(key[j]) - 65
        crypted.append(cesar(operation, key_value, char))
        if char.upper() in string.ascii_uppercase:
            j = (j + 1) % len(key)
    return crypted

def bytes_to_letters(byte_data):
    alphabet = string.ascii_uppercase
    return "".join(alphabet[b % 26] for b in byte_data)

def generateBytes(nBytes, filenameBytes):
    bytes = os.urandom(nBytes)
    with open(filenameBytes, 'wb') as f:
        f.write(bytes)

def encrypt(fToEncrypted, fKey):
    with open(fToEncrypted, 'r') as f:
        lines = f.read()
    with open(fKey, 'rb') as f:
        keyB = f.read()
        key = bytes_to_letters(keyB)
    crypted = vigenere(1, key, lines)
    with open(fToEncrypted + '.enc', 'w') as f:
        f.write(''.join(crypted))  

def decrypt(fToDecrypted, fKey):
    with open(fToDecrypted, 'r') as f:
        lines = f.read()
    with open(fKey, 'rb') as f:
        keyB = f.read()
        key = bytes_to_letters(keyB)
    decrypted = vigenere(-1, key, lines)
    with open(fToDecrypted + '.dec', 'w') as f:
        f.write(''.join(decrypted))  

def main(args):
    if len(args) < 2:
        print("Error")
        return
    match args[1]:
        case 'setup':
            nBytes = int(args[2])
            filenameBytes = args[3]
            generateBytes(nBytes, filenameBytes)
        case 'enc':
            filenameToEncrypted = args[2]
            filenameKey = args[3]
            encrypt(filenameToEncrypted, filenameKey)
        case 'dec':
            filenameToDecrypted = args[2]
            filenameKey = args[3]
            decrypt(filenameToDecrypted, filenameKey)
        case _:
            print("Error")

if __name__ == "__main__":
    main(sys.argv)

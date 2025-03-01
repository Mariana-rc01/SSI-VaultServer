import sys
from cesar import *

def vigenere (operation, key, text):
    j = 0
    crypted = []
    for i in range(len(text)):
        value = ord(key[j]) - 65
        crypted.append(cesar(operation, value, text[i])[0])
        j = (j + 1) % len(key)
    return crypted

def main(args):
    operation = args[1]
    if (operation == 'enc') : op = 1
    else: op = -1
    key = args[2].upper()
    text = args[3].upper()
    crypted = vigenere(op, key, text)
    print("".join(crypted))

if __name__ == "__main__":
    main(sys.argv)
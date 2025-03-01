import sys, random
from otp import *

def bad_prng(n):
    random.seed(random.randbytes(2))
    return random.randbytes(n)

def generateBytesB(nBytes, filenameBytes):
    bytes = bad_prng(nBytes)
    with open(filenameBytes, 'wb') as f:
        f.write(bytes)

def main(args):
    if len(args) < 2:
        print("Error")
        return
    match args[1]:
        case 'setup':
            nBytes = int(args[2])
            filenameBytes = args[3]
            generateBytesB(nBytes, filenameBytes)
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


if __name__ == '__main__':
    main(sys.argv)
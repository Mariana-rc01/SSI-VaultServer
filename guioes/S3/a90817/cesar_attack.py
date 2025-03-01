import sys
from cesar import *

def main(args):
    cryptogram = args[1].upper()
    for arg in args[2:]:
        for i in range(0,26):
            cryted = cesar(1,i,arg)
            if "".join(cryted) in cryptogram:
                decrypted = cesar(-1,i,cryptogram)
                print(chr(i + 65))
                print("".join(decrypted))
                break

if __name__ == "__main__":
    main(sys.argv)
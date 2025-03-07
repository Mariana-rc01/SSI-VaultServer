import sys

def change(file, pos, textBefore, textAfter):
    with open(file, 'rb') as f:
        text = f.read()

    nonce = text[:16]
    cipherText = text[16:]

    binaryB = textBefore.encode()
    binaryA = textAfter.encode()

    length = len(binaryB)
    start = pos

    if length != len(binaryA):
        print("Error: The length of the new plaintext must be the same as the old plaintext.")
        return

    if start + length > len(cipherText):
        print("Error: Attack position and length are out of bounds.")
        return

    attackedCipherText = bytearray(cipherText)

    for i in range(length):
        attackedCipherText[start + i] += binaryB[i] ^ binaryA[i]

    with open(file + '.attack', 'wb') as f:
        f.write(nonce)
        f.write(attackedCipherText)

def main(args):
    fileEncrypted = args[1]
    position = int(args[2])
    ptxtAtPos = args[3]
    newPtxtAtPos = args[4]
    change(fileEncrypted, position, ptxtAtPos, newPtxtAtPos)

if __name__ == "__main__":
    main(sys.argv)
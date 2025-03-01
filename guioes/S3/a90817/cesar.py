import sys

def cesar (operation, key, text):
    crypted = []
    for c in text:
        if c.isalpha():
            crypted.append(chr((ord(c) - 65 + operation * key) % 26 + 65))
        else:
            crypted.append(c)
    return crypted

def main(args):
    operation = args[1]
    if (operation == 'enc') : op = 1
    else: op = -1
    key = args[2]
    text = args[3].upper()
    value = ord(key) - ord('A')
    crypted = cesar(op, value, text)
    print("".join(crypted))

if __name__ == "__main__":
    main(sys.argv)
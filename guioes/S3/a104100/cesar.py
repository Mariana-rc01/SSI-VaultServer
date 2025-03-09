import sys

def preproc(str):
    l = []
    for c in str:
        if c.isalpha():
            l.append(c.upper())
    return "".join(l)

def main(args):
    direction = args[1]
    key = args[2]
    text = preproc(args[3])

    operation = 0
    if direction == "dec":
        operation = -1
    else:
        operation = 1

    cryped = []
    for c in text:
        cryped.append(chr((ord(c) - ord('A') + ((ord(key)- ord('A'))*operation)) % 26 + 65))

    print("".join(cryped))

if __name__ == "__main__":
    main(sys.argv)
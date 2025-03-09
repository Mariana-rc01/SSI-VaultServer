def preproc(str):
    l = []
    for c in str:
        if c.isalpha():
            l.append(c.upper())
    return "".join(l)

import sys

def cesar(op, key, msg):
    msg = preproc(msg)
    if op == "enc":
        return "".join([chr((ord(c) - 65 + ord(key) - 65) % 26 + 65) for c in msg])
    elif op == "dec":
        return "".join([chr((ord(c) - 65 - ord(key) - 65) % 26 + 65) for c in msg])
    else:
        return "Operação inválida"

def cesar_attack(msg, ana):
    res = []
    char = ''
    for i in range(0,27):
        temp = cesar("dec", chr(i + 65), msg)
        for word in ana:
            if word in temp:
                res.append(temp)
                char = chr(i + 65)
    return res, char

if __name__ == "__main__":
    result, char = cesar_attack(sys.argv[1], sys.argv[2:])
    if len(result) > 0:
        print(result[0])
        print(char)

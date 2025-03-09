def preproc(str):
    l = []
    for c in str:
        if c.isalpha():
            l.append(c.upper())
    return "".join(l)

def cesar(op, key, msg):
    msg = preproc(msg)
    if op == "enc":
        return "".join([chr((ord(c) - 65 + ord(key) - 65) % 26 + 65) for c in msg])
    elif op == "dec":
        return "".join([chr((ord(c) - 65 - ord(key) - 65) % 26 + 65) for c in msg])
    else:
        return "Operação inválida"
    
import sys

def vigenere(op, key, msg):
    j = 0
    res = []
    for i in range(len(msg)):
        value = key[j]
        res.append(cesar(op, value, msg[i]))
        j = (j + 1) % len(key)
    return "".join(res)
    
if __name__ == "__main__":
    result = vigenere(sys.argv[1], sys.argv[2], sys.argv[3])
    print(result)
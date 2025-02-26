def preproc(str):
    l = []
    for c in str:
        if c.isalpha():
            l.append(c.upper())
    return "".join(l)

"""
Escrever o programa cesar.py que receba 3 argumentos

o tipo de operação a realizar: enc ou dec
a chave secreta: A , B , ..., Z
a mensagem a cifrar, por exemplo "Cartago esta no papo".

Apresenta-se de seguida um exemplo de utilização para este programa, através do terminal:

 python3 cesar.py enc G "CartagoEstaNoPapo"
IGXZGMUKYZGTUVGVU
$ python3 cesar.py dec G "IGXZGMUKYZGTUVGVU"
CARTAGOESTANOPAPO
"""

import sys

def cesar(op, key, msg):
    msg = preproc(msg)
    if op == "enc":
        return "".join([chr((ord(c) - 65 + ord(key) - 65) % 26 + 65) for c in msg])
    elif op == "dec":
        return "".join([chr((ord(c) - 65 - ord(key) - 65) % 26 + 65) for c in msg])
    else:
        return "Operação inválida"
    
if __name__ == "__main__":
    print(cesar(sys.argv[1], sys.argv[2], sys.argv[3]))

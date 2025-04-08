#!/bin/bash

# Exercício 1
getfacl porto.txt

# Exercício 2
setfacl -m g:grupo-ssi:rw porto.txt

# Exercício 3
# Para além das definições default do sistema é possível ver que os utilizadores do grupo grupo-ssi têm acesso de leitura e escrita no ficheiro.

# Exercício 4

#!/bin/bash

# Exercício 1
getfacl porto.txt

# Exercício 2
setfacl -m g:grupo-ssi:rw porto.txt

# Exercício 3
# Foi adicionado o grupo grupo-ssi, consigo perceber isso através da linha: group:grupo-ssi:rw-

# Exercício 4
su helder
vim porto.txt
# Não é possível, pois o utilizador não tem permissões de escrita no ficheiro porto.txt

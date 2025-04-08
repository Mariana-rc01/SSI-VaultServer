#!/bin/bash

# Exercício 1
gcc -o mycat mycat.c

# Exercício 2
sudo adduser userssi

# Exercício 3
sudo chown userssi mycat
sudo chown userssi braga.txt

# Exercício 4
./mycat braga.txt

# Exercício 5
su userssi
chmod u+s mycat
exit

# Exercício 6
# Agora já é possível ler o conteúdo do ficheiro porque os privilégios foram elevados ao do dono do ficheiro.

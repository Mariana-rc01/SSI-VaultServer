#!/bin/bash

# Exercício 1
# Criei o programa main.c que me cria um executável que imprime o conteúdo de um ficheiro.
gcc main.c

# Exercício 2
sudo adduser userssi

# Exercício 3
sudo chown userssi braga.txt
sudo chown userssi a.out

# Exercício 4
exit
./a.out braga.txt
# Não consegui, pois a permissão de execução do ficheiro não está atribuída ao utilizador.

# Exercício 5
sudo chmod u+s s.out

# Exercício 6
./imprime braga.txt
# Devido à flag s, foram elevadas as permissões do user core, para as mesmas do dono do ficheiro (userssi), possibilitando a sua leitura

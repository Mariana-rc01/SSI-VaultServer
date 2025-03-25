#!/bin/bash

# Exercício 0
cat /etc/passwd
cat /etc/group

# Exercício 1
sudo adduser helder
sudo adduser pedro
sudo adduser mariana

# Exercício 2
sudo groupadd grupo-ssi
sudo gpasswd grupo-ssi
sudo usermod -a -G grupo-ssi helder
sudo usermod -a -G grupo-ssi pedro
sudo usermod -a -G grupo-ssi mariana
sudo groupadd par-ssi
sudo gpasswd par-ssi
sudo usermod -a -G par-ssi helder
sudo usermod -a -G par-ssi pedro

# Exercício 3
# No ficheiro /etc/passwd, foram criados os 3 users (helder, pedro, mariana). No ficheiro /etc/group, foram criados os 2 grupos, grupo-ssi, com os utilizadores (helder, pedro, mariana) e o grupo par-ssi (helder e pedro)).

# Exercício 4
sudo chown helder braga.txt

# Exercício 5
cat braga.txt

# Exercício 6
su helder

# Exercício 7
id
# Com o comando id foi impresso o meu id e os grupos a que pertenço.
groups
# Com o comando groups foi impresso os grupos a que pertenço.

# Exercício 8
cat braga.txt
# O utilizador tem permissões de leitura no ficheiro braga.txt, por isso consegue ler o ficheiro.

# Exercício 9
cd dir2
# O utilizador não tem permissões de execução no diretório dir2, por isso não consegue aceder à diretoria.
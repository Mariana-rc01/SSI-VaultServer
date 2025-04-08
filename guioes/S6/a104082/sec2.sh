#!/bin/bash

# Exercício 0
cat /etc/passwd
cat /etc/group

# Exercício 1
sudo adduser pedro
sudo adduser helder
sudo adduser mariana

# Exercício 2
sudo groupadd grupo-ssi
sudo gpasswd grupo-ssi

sudo usermod -a -G grupo-ssi pedro 
sudo usermod -a -G grupo-ssi helder 
sudo usermod -a -G grupo-ssi mariana

sudo groupadd par-ssi
sudo gpasswd par-ssi

sudo usermod -a -G par-ssi pedro
sudo usermod -a -G par-ssi helder

# Exercício 3
# No final dos ficheiros /etc/passwd e /etc/group estão as novas entradas dos utilizadores e grupos.

# Exercício 4
sudo chown pedro braga.txt

# Exercício 5
cat braga.txt

# Exercício 6
su pedro

# Exercício 7
id
# Se correr id, vejo o meu identificador e os grupos a que faço parte.
groups
# Se correr groups, vejo os grupos disponíveis no sistema.

# Exercício 8
cat braga.txt
# Como estou no user que tem permissões de leitura (novo owner do ficheiro) já consigo ver o conteúdo do ficheiro.

# Exercício 9
cd dir2/
# Não tenho permissões de acesso porque num exercício anterior retirei as permissões de acesso a todos os outros users do sistema.

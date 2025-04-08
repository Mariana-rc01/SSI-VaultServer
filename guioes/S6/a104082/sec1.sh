#!/bin/bash

# Exercício 1
touch lisboa.txt porto.txt braga.txt

echo "Exemplo de texto!" > lisboa.txt 
echo "Exemplo de texto!" > porto.txt 
echo "Exemplo de texto!" > braga.txt

# Exercício 2
ls -l lisboa.txt

# Exercício 3
chmod a+w lisboa.txt

# Exercício 4
chmod u+rx-w porto.txt

# Exercício 5
chmod 620 braga.txt

# Exercício 6
mkdir dir1 dir2
ls -ld dir1 dir2

# Exercício 7
chmod -075 dir2

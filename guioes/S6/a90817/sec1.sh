#!/bin/bash

# Exercise 1
touch lisboa.txt porto.txt braga.txt
echo "Exemplo" > lisboa.txt | echo "Exemplo1" > porto.txt | echo "Exemplo2" > braga.txt

# Exercise 2

ls -l lisboa.txt

# Exercise 3

chmod 0666 lisboa.txt

# Exercise 4

chmod u+rx-w porto.txt

# Exercise 5

chmod 0400 braga.txt

# Exercise 6

mkdir dir1 dir2
cd dir1
touch t
cd ..
cd dir2
touch t1
cd ..
ls -ld dir1 dir2

# Exercise 7

chmod -R 744 dir2

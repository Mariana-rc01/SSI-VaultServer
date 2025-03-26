#!/bin/bash

# Exercise 0

cat /etc/passwd
cat /etc/group

# Exercise 1

sudo adduser mariana
sudo adduser pedro
sudo adduser helder

# Exercise 2

sudo groupadd grupo-ssi
sudo gpasswd grupo-ssi
sudo usermod -a -G grupo-ssi mariana
sudo usermod -a -G grupo-ssi pedro
sudo usermod -a -G grupo-ssi helder

sudo groupadd par-ssi
sudo usermod -a -G par-ssi pedro
sudo usermod -a -G par-ssi helder

# Exercise 3

# The users mariana, pedro, and helder were added to /etc/passwd.
# In /etc/group, we have the default groups for each user and the newly created groups grupo-ssi and par-ssi.
# The grupo-ssi group includes mariana, pedro, and helder, while the par-ssi group includes pedro and helder.

# Exercise 4

sudo chown mariana braga.txt

# Exercise 5

cat braga.txt

# Exercise 6

su mariana

# Exercise 7

id
# uid=1001(mariana) gid=1001(mariana) groups=1001(mariana),1004(grupo-ssi)

groups
#mariana grupo-ssi

# Comment the results

# Exercise 8

cat braga.txt
# Yes, now we can see the content of the file because mariana is the owner and has the necessary permissions.

# Exercise 9

mv braga.txt dir2

# The mariana user doesn't have permissions over dir2 directory.

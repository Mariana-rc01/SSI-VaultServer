#!/bin/bash

# Exercise 1

getfacl porto.txt
# # file: porto.txt
# # owner: core
# # group: core
# user::r-x
# group::r--
# other::r--

# Exercise 2

sudo setfacl -m g:grupo-ssi:rw porto.txt

# Exercise 3

sudo getfacl porto.txt
# # file: porto.txt
# # owner: core
# # group: core
# user::r-x
# group::r--
# group:grupo-ssi:rw-
# mask::rw-
# other::r--

# The grupo-ssi group now has write permission on porto.txt.

# Exercise 4

su mariana
cat porto.txt
# Exemplo1

vim porto.txt
# Exemplo1234

cat porto.txt
# Exemplo1


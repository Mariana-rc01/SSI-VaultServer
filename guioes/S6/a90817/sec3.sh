#!/bin/bash

# Exercise 1

touch binary.c

# binary.c:
# #include <stdio.h>
# #include <stdlib.h>
# 
# int main(int argc, char *argv[]) {
# 	FILE *file = fopen(argv[1],"r");
# 	if(file == NULL) {
# 		perror("Error opening file");
# 		return 1;
# 	}
# 
# 	char ch;
# 	while((ch = fgetc(file)) != EOF){
# 		putchar(ch);
# 	}
# 
# 	fclose(file);
# 	return 0;
# }
gcc -o binary binary.c

# Exercise 2

sudo adduser userssi

# Exercise 3

sudo chown userssi braga.txt
sudo chown userssi binary

# Exercise 4

./binary braga.txt

#Error opening file: Permission denied

# Exercise 5

sudo chmod u+s binary

# Exercise 6

./binary braga.txt 
#Exemplo2

# By setting the setuid permission on the executable file, it will run with the 
# privileges of the file's owner, allowing userssi to execute the binary with 
# elevated permissions.


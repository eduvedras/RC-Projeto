# Makefile
# Redes de Computadores, Grupo:01 LEIC-A 2021/2022

CC   = gcc
CFLAGS =-g -Wall

.PHONY: all clean

all: user DS

user: user.c user.h
	$(CC) $(CFLAGS) user.c -o user

DS: DS.c DS.h
	$(CC) $(CFLAGS) DS.c -o DS

clean:
	@echo Cleaning...
	rm -rf downloads
	rm -rf GROUPS
	rm -rf USERS
	rm -f user
	rm -f DS
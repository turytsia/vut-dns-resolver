PROJ_D=$(shell pwd)
SRC=dns.c
OUT=dns
CC=gcc
CFLAGS=-Wall -Wextra -std=c89 -pedantic -Wmissing-prototypes -Wstrict-prototypes \
    -Wold-style-definition

ifeq ($(OS),Windows_NT)
run:
	echo "Not supported"
else
run:
	$(CC) $(SRC) -o $(OUT)
endif

clean:
	echo "No tests"
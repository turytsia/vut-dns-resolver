OUT=dns
CC=gcc
CFLAGS=-Wall -Wextra -Werror -std=c99 -pedantic -Wmissing-prototypes -Wstrict-prototypes \
    -Wold-style-definition

ifeq ($(OS),Windows_NT)
run:
	@echo "Not supported."
else
run:
	@$(CC) $(CFLAGS) $(shell find ./* -name '*.c') -o $(OUT)
endif

test: # chmod +x test.sh
	@bash ./test.sh

clean:
	@rm dns
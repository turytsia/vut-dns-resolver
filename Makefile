OUT=dns
CC=gcc
CFLAGS=-Wall -Wextra -Werror -std=c99 -pedantic -Wmissing-prototypes -Wstrict-prototypes \
    -Wold-style-definition

run:
	$(CC) $(CFLAGS) $(shell find ./* -name '*.c') -o $(OUT)

test: # chmod +x test.sh
	bash ./test.sh

clean:
	rm dns
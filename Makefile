# author: Oleksandr Turytsia (xturyt00)

LOGIN=xturyt00
OUT=dns
CC=gcc
CFLAGS=-Wall -Wextra -Werror -std=c99 -pedantic -Wmissing-prototypes -Wstrict-prototypes \
    -Wold-style-definition

run:
	$(CC) $(CFLAGS) ./src/args.c ./src/dns.c ./src/error.c ./src/utils.c -o $(OUT)

test: # chmod +x test.sh
	bash ./test.sh

clean:
	rm dns
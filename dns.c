#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

typedef struct {
    int recursive;
    int reverse;
    int ipv6;
    int port;
    char source_addr[255];
    char target_addr[255];
} args_t;

int getopt(args_t* args, int argc, char** argv) {

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0) {
            args->recursive = 1;
        }
        else if (strcmp(argv[i], "-6") == 0) {
            args->ipv6 = 1;
        }
        else if (strcmp(argv[i], "-x") == 0) {
            args->reverse = 1;
        }
        else if (strcmp(argv[i], "-s") == 0) {
            if (i + 1 >= argc) return 1;

            strcpy(args->source_addr, argv[++i]);
        }
        else if (strcmp(argv[i], "-p") == 0) {
            if (i + 1 >= argc) return 1;

            int port = atoi(argv[++i]);

            if (port == 0) return 1;

            args->port = port;
        }
        else if (i == argc - 1) {
            strcpy(args->target_addr, argv[i]);
        }
    }

    return 0;
}

int main(int argc, char** argv) {

    args_t args = { .port = 53 };
    
    int err = getopt(&args, argc, argv);
    if (err) {
        printf("Error occured\n");
        exit(err);
    }

    printf("Recursive: %d\n", args.recursive);
    printf("Reverse: %d\n", args.reverse);
    printf("Ipv6: %d\n", args.ipv6);
    printf("Port: %d\n", args.port);
    printf("Source IP: %s\n", args.source_addr);
    printf("Target IP: %s\n", args.target_addr);

    return 0;
}
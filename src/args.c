#include "args.h"

/**
 *
 */
int get_ai_family(args_t* args) {
    return args->ipv6 == 1 ? AF_INET6 : AF_INET;
}

/**
 * 
 */
err_t getopts(args_t* args, int argc, char** argv) {
    // Reset args
    memset(args, 0, sizeof(args_t));

    // Set up default arguments
    strcpy(args->port, "53");

    // Read program arguments
    for (int i = 1; i < argc; i++) {
        const char* arg = argv[i];
        
        if (strcmp(arg, "-r") == 0) {
            args->recursive = 1;
        }
        else if (strcmp(arg, "-6") == 0) {
            args->ipv6 = 1;
        }
        else if (strcmp(arg, "-x") == 0) {
            args->reverse = 1;
        }
        else if (strcmp(arg, "-s") == 0) {
            if (i + 1 >= argc) {
                return SOURCE_MISSING;
            }

            strcpy(args->source_addr, argv[++i]);
        }
        else if (strcmp(arg, "-p") == 0) {
            if (i + 1 >= argc) {
                return PORT_MISSING;
            }

            int port = atoi(argv[++i]);

            if (port <= 0) {
                return INVALID_PORT;
            }

            snprintf(args->port, sizeof(args->port), "%d", port);
        }
        else if (i == argc - 1) {
            strcpy(args->target_addr, arg);
        }
        else {
            return UNKNOWN_OPTION;
        }
    }

    if (args->target_addr == 0) {
        return TARGET_MISSING;
    }

    return OK;
}
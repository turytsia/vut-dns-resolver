#include "args.h"

/**
 * 
 */
void getopts(args_t* args, int argc, char** argv) {

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
                exit_error(1, "Source address is not specified.");
            }

            strcpy(args->source_addr, argv[++i]);
        }
        else if (strcmp(arg, "-p") == 0) {
            if (i + 1 >= argc) {
                exit_error(1, "Port is not specified.");
            }

            int port = atoi(argv[++i]);

            if (port <= 0) {
                exit_error(1, "Port is not valid.");
            }

            snprintf(args->port, sizeof(args->port), "%d", port);
        }
        else if (i == argc - 1) {
            strcpy(args->target_addr, arg);
        }
        else {
            exit_error(1, "Unknown option.");
        }
    }

    if (args->target_addr == 0) {
        exit_error(1, "Target address is not specified.");
    }
}
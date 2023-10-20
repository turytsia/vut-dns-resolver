#include "args.h"

/**
 * @file args.c
 * @brief Command-Line Argument Parsing Implementation
 *
 * This C source file, "args.c," contains the implementation of a function named `getopts`. The
 * purpose of this function is to parse and validate command-line arguments and populate an
 * `args_t` structure with the specified options and addresses.
 *
 * The function iterates through the command-line arguments and handles the following options:
 * - `-r`: Enable recursion
 * - `-6`: Enable IPv6 mode
 * - `-x`: Perform a reverse query
 * - `-s`: Set the source address for the query
 * - `-p`: Set the port number for the query
 * The default port is set to 53 if not specified.
 *
 * The function returns an error code (args_err_t) to indicate the success or failure of the
 * argument parsing process. Possible errors include unknown options, invalid port numbers,
 * missing required arguments, and more.
 *
 * @author Oleksandr Turytsia (xturyt00)
 * @date October 18, 2023
 */
args_err_t getopts(args_t* args, int argc, char** argv) {

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
                return E_SRC_MISS;
            }

            strcpy(args->source_addr, argv[++i]);
        }
        else if (strcmp(arg, "-p") == 0) {
            if (i + 1 >= argc) {
                return E_PORT_MISS;
            }

            int port = atoi(argv[++i]);

            if (port <= 0 || port > 65535) {
                return E_PORT_INV;
            }

            strcpy(args->port, argv[i]);
        }
        else if (i == argc - 1) {
            strcpy(args->target_addr, arg);
        }
        else {
            return E_UNKNOWN_OPT;
        }
    }

    if (strlen(args->target_addr) == 0) {
        return E_TGT_MISS;
    }

    return 0;
}
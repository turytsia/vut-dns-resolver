/**
 * @file args.h
 * @brief Command-Line Argument Parsing Header
 *
 * This C header file, "args.h" provides the structure definition for storing command-line
 * arguments and declares functions related to parsing and handling command-line arguments. It
 * includes a structure, `args_t`, that contains various options and arguments required for
 * configuring a DNS query, such as recursion, reverse query, IPv6 mode, port number, source
 * address, and target address.
 *
 * Additionally, the file declares the function `getopts`, which is responsible for parsing
 * and validating command-line arguments and populating the `args_t` structure. Any errors
 * encountered during argument parsing are indicated using error codes.
 *
 * @author Oleksandr Turytsia (xturyt00)
 * @date October 18, 2023
 */
#ifndef ARGS_H
#define ARGS_H

#include "error.h"
#include "libs.h"

typedef struct {
    int recursive;
    int reverse;
    int ipv6;
    int test;
    char port[256];
    char source_addr[256];
    char target_addr[256];
} args_t;

args_err_t getopts(args_t* args, int argc, char** argv);

#endif
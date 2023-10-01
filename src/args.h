#ifndef ARGS_H
#define ARGS_H

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "common.h"

typedef struct {
    int recursive;
    int reverse;
    int ipv6;
    char port[255];
    char source_addr[255];
    char target_addr[255];
} args_t;

err_t getopts(args_t*, int, char**);

int get_ai_family(args_t*);

#endif
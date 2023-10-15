#ifndef ERROR_H
#define ERROR_H

#include <stdlib.h>
#include <stdio.h>

typedef enum {
    OK = 0,
    UNKNOWN_OPTION,
    INVALID_PORT,
    PORT_MISSING,
    SOURCE_MISSING,
    TARGET_MISSING
} err_t;

void exit_error(err_t err, const char* message);

#endif
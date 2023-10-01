#ifndef COMMON_H
#define COMMON_H

typedef enum {
    OK = 0,
    UNKNOWN_OPTION,
    INVALID_PORT,
    PORT_MISSING,
    SOURCE_MISSING,
    TARGET_MISSING
} err_t;

#endif
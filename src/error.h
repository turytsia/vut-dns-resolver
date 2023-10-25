/**
 * @file error.h
 * @brief DNS Query Error Handling Header
 *
 * This C header file, "error.h" defines error codes and a function for handling errors
 * in a DNS query utility. It includes error code enumerations for different types of
 * errors, such as command-line argument validation, DNS query sending, address resolution,
 * and DNS response handling. The file also provides a function to report and handle errors
 * with descriptive error messages.
 *
 * @author Oleksandr Turytsia (xturyt00)
 * @date October 18, 2023
 */
#ifndef ERROR_H
#define ERROR_H

#include <stdlib.h>
#include <stdio.h>

typedef enum {
    E_UNKNOWN_OPT = 1,
    E_PORT_INV = 2,
    E_PORT_MISS = 3,
    E_SRC_MISS = 4,
    E_TGT_MISS = 5,
    E_OPT_DOUBLE = 6
} args_err_t;

typedef enum {
    E_SOCK = 10,
    E_SENDTO = 11,
    E_TIMEOUT = 12,
    E_RECVFROM = 13,
} send_query_err_t;

typedef enum {
    E_EAI = 20,
    E_GAI = 21,
    E_FAMILY = 22,
} other_err_t;

typedef enum {
    E_FORMAT = 31,
    E_SERVER_FAIL = 32,
    E_NAME = 33,
    E_NOT_IMPL = 34,
    E_REFUSED = 35,
} rcode_err_t;

void exit_error(int err, const char* message);

#endif
/**
 * @file utils.h
 * @brief Utility Functions for DNS Query Program
 *
 * This C source file, "utils.c," contains various utility functions used by the DNS query program. It defines
 * several enumerated types and provides functions to work with DNS-related data, such as DNS types, classes,
 * and resource record (RR) codes.
 *
 * The file defines the following enumerated types:
 * - `type_t`: Enumerates DNS record types, such as A, AAAA, PTR, etc.
 * - `class_t`: Enumerates DNS record classes, such as IN, CS, CH, HS.
 * - `rcode_t`: Enumerates DNS response codes (RCODEs), such as format error, server failure, etc.
 *
 * The utility functions in this file include functions to:
 * - Get the DNS class name for a given class code.
 * - Get the DNS type name for a given type code.
 * - Print a DNS packet for debugging purposes.
 * - Convert a boolean value to "yes" or "no" string.
 * - Determine the length of a DNS domain name.
 * - Check if a DNS type or class is valid.
 *
 * These utility functions are used to enhance the readability and maintainability of the main DNS query program.
 *
 * @author Oleksandr Turytsia (xturyt00)
 * @date October 18, 2023
 */
#ifndef UTILS_H
#define UTILS_H

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

typedef enum {
    A = 1,
    NS,
    MD,
    MF,
    CNAME,
    SOA,
    MB,
    MG,
    MR,
    NIL,
    WKS,
    PTR,
    HINFO,
    MINFO,
    MX,
    TXT,
    AAAA = 28
} type_t;

typedef enum {
    IN = 1,
    CS,
    CH,
    HS
} class_t;

typedef enum {
    RCODE_FORMAT_ERROR = 1,
    RCODE_SERVER_FAILURE,
    RCODE_NAME_ERROR,
    RCODE_NOT_IMPLEMENTED,
    RCODE_REFUCED
} rcode_t;

const char* get_dns_class(unsigned short class);
const char* get_dns_type(unsigned short type);
void print_packet(unsigned char* packet, int len);
const char* bool_to_yes_no(int value);
int get_name_length(unsigned char* pointer_to_name, char* name);
int is_type_valid(unsigned short type);
int is_class_valid(unsigned short type);

#endif
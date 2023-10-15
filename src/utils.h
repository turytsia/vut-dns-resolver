#ifndef UTILS_H
#define UTILS_H

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

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

const char* get_dns_class(unsigned short class);
const char* get_dns_type(unsigned short type);
void print_packet(unsigned char* packet, int len);
const char* bool_to_yes_no(int value);

#endif
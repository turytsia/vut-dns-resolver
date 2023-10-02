#ifndef DNS_H
#define DNS_H

#include "args.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <ctype.h>
#include <errno.h>

#define MAX_TYPE 16
#define MIN_TYPE 1
#define MAX_CLASS 4
#define MIN_CLASS 1

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
    TXT
} type_t;

typedef enum {
    IN = 1,
    CS,
    CH,
    HS
} class_t;

const char* type_names[] = {
    [A] = "A",
    [NS] = "NS",
    [MD] = "MD",
    [MF] = "MF",
    [CNAME] = "CNAME",
    [SOA] = "SOA",
    [MB] = "MB",
    [MG] = "MG",
    [MR] = "MR",
    [NIL] = "NIL",
    [WKS] = "WKS",
    [PTR] = "PTR",
    [HINFO] = "HINFO",
    [MINFO] = "MINFO",
    [MX] = "MX",
    [TXT] = "TXT"
};

const char* class_names[] = {
    [IN] = "IN",
    [CS] = "CS",
    [CH] = "CH",
    [HS] = "HS"
};

typedef struct {
    unsigned short id;

    unsigned char rd : 1;
    unsigned char tc : 1;
    unsigned char aa : 1;
    unsigned char opcode : 4;
    unsigned char qr : 1;

    unsigned char rcode : 4;
    unsigned char cd : 1;
    unsigned char ad : 1;
    unsigned char z : 1;
    unsigned char ra : 1;

    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
} dns_header_t;

typedef struct {
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short data_len;
} dns_rr_t;

typedef struct {
    unsigned short qtype;
    unsigned short qclass;
} dns_question_t;

#endif
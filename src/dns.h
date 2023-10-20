/**
 * @file dns.h
 * @brief DNS Query Utility Header
 *
 * This C header file, "dns.h," defines data structures and function prototypes used in
 * the DNS query utility. It includes structures for DNS header, resource records, question
 * sections, and SOA (Start of Authority) resource data. Additionally, it provides function
 * declarations for DNS query creation, DNS query sending, parsing DNS responses, and various
 * utility functions for working with DNS data.
 *
 * @author Oleksandr Turytsia (xturyt00)
 * @date October 18, 2023
 */
#ifndef DNS_H
#define DNS_H

#define _POSIX_C_SOURCE 200112L

#include "args.h"
#include "utils.h"

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
#include <sys/time.h>

#define MAX_BUFF 65536
#define MAX_NAME 256

// Header section format
#pragma pack(1)
typedef struct {
    unsigned short id: 16;          // DNS Identifier

    unsigned char rd : 1;           // Recursion Desired
    unsigned char tc : 1;           // Truncated Response
    unsigned char aa : 1;           // Authoritative Answer
    unsigned char opcode : 4;       // Operation Code
    unsigned char qr : 1;           // Query/Response Flag

    unsigned char rcode : 4;        // Response Code
    unsigned char cd : 1;           // Checking Disabled
    unsigned char ad : 1;           // Authenticated Data
    unsigned char z : 1;            // Reserved
    unsigned char ra : 1;           // Recursion Available

    unsigned short qdcount : 16;    // Question Count
    unsigned short ancount : 16;    // Answer Record Count
    unsigned short nscount : 16;    // Authority Record Count
    unsigned short arcount : 16;    // Additional Record Count
} dns_header_t;
#pragma pack()

// Resource record format
#pragma pack(1)
typedef struct {
    unsigned short type : 16;       // Data type at RDATA
    unsigned short class : 16;      // Class of the data at RDATA field    
    unsigned int ttl : 32;          // TTL
    unsigned short rdlength : 16;   // RDATA length
} dns_rr_t;
#pragma pack()

// Question section format
#pragma pack(1)
typedef struct {
    unsigned short qtype : 16;      // Type of the query
    unsigned short qclass : 16;     // Class of the query
} dns_question_t;
#pragma pack()

// SOA RDATA format
#pragma pack(1)
typedef struct {
    unsigned int serial;            // Verstion number of the zone
    unsigned int refresh;           // Time interval before the zone should be refreshed
    unsigned int retry;             // Time interval that should elapse before a failed refresh should be retried
    unsigned int expire;            // Time value that specifies the upper limit on the time interval that can elapse before the zone is no longer authoritative
    unsigned int min_ttl;           // Minimum TTL
} dns_soa_t;
#pragma pack()

void parse_domain_name(unsigned char* packet, unsigned char* buffer, char* result);
void create_dns_query(args_t* args, unsigned char* query);
send_query_err_t send_dns_query(args_t* args, int ai_family, unsigned char* buffer, unsigned char* query, char* addr, int qlen);
void compress(unsigned char* dest, char* src, int len);
void compress_domain_name(unsigned char* dest, char* src);
void print_rr(unsigned char* pointer, unsigned char* buffer, int n);
void reverse_dns_ipv6(char* dest, char* addr);
void reverse_dns_ipv4(char* dest, char* addr);

void print_ipv4_data(unsigned char* pointer);
void print_ipv6_data(unsigned char* pointer);
void print_soa_data(unsigned char* pointer, unsigned char* buffer);
void print_domain_name_data(unsigned char* pointer, unsigned char* buffer);

#endif
/**
 * @file utils.c
 * @brief Utility Functions for DNS Query Program
 *
 * This C source file, "utils.c," contains utility functions used by the DNS query program to work with DNS-related
 * data. These utility functions are designed to enhance the readability, maintainability, and functionality of the
 * main DNS query program.
 *
 * The file defines and provides the following utility functions:
 * - `const char* get_dns_class(unsigned short class)`: Returns the DNS class name for a given class code, or "Not supported" if invalid.
 * - `const char* get_dns_type(unsigned short type)`: Returns the DNS type name for a given type code, or "Not supported" if invalid.
 * - `void print_packet(unsigned char* packet, int len)`: Prints a formatted representation of a DNS packet for debugging.
 * - `const char* bool_to_yes_no(int value)`: Converts a boolean value to a "Yes" or "No" string.
 * - `int get_name_length(unsigned char* pointer_to_name, char* name)`: Determines the length of a DNS domain name.
 * - `int is_type_valid(unsigned short type)`: Checks if a DNS type is valid.
 * - `int is_class_valid(unsigned short type)`: Checks if a DNS class is valid.
 *
 * The file also defines arrays (`type_names` and `class_names`) to map DNS type and class codes to their string representations.
 *
 * These utility functions provide essential functionality for parsing, displaying, and validating DNS-related data in the DNS
 * query program. They contribute to the overall robustness of the program and facilitate easier debugging and interpretation
 * of DNS responses.
 *
 * @author Oleksandr Turytsia (xturyt00)
 * @date October 18, 2023
 */
#include "utils.h"

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
    [TXT] = "TXT",
    [AAAA] = "AAAA"
};

const char* class_names[] = {
    [IN] = "IN",
    [CS] = "CS",
    [CH] = "CH",
    [HS] = "HS"
};

int is_type_valid(unsigned short type) {
    switch(type){
        case A:
        case NS:
        case MD:
        case MF:
        case CNAME:
        case SOA:
        case MB:
        case MG:
        case MR:
        case NIL:
        case WKS:
        case PTR:
        case HINFO:
        case MINFO:
        case MX:
        case TXT:
        case AAAA:
            return 1;
        default:
            return 0;
    }
}

int is_class_valid(unsigned short type) {
    switch(type){
        case IN:
        case CS:
        case CH:
        case HS:
            return 1;
        default:
            return 0;
    }
}

const char* get_dns_class(unsigned short class) {
    if(!is_class_valid(class))
        return "Not supported";

    return class_names[class];
}

const char* get_dns_type(unsigned short type) {
    if(!is_type_valid(type))
        return "Not supported";

    return type_names[type];
}

void print_packet(unsigned char* packet, int len) {
    int i, j, cols;
    for (i = 0; i < len; i += 16) {
        printf("\n0x%04x:", i);

        cols = i + 16;

        for (j = i; j < cols; j++) {
            if (j < len)
                printf(" %02x", packet[j]);
            else
                printf("   ");
        }
        printf(" ");
        for (j = i; cols < len ? j < cols : j < len; j++)
            printf("%c", isprint(packet[j]) ? packet[j] : '.');
    }
    printf("\n");
}

const char* bool_to_yes_no(int value) {
    return value ? "Yes" : "No";
}

int get_name_length(unsigned char* pointer_to_name, char* name) {
    return (*pointer_to_name & 192) == 192 ? 2 : strlen(name) + 1;
}
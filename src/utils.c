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

const char* get_dns_class(unsigned short class) {
    return class_names[class];
}

const char* get_dns_type(unsigned short type) {
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
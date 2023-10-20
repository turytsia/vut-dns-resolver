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

/**
 * @brief Check if a DNS resource record type is valid.
 *
 * This function checks whether a DNS resource record type, represented as an unsigned short 'type',
 * is valid or not. It returns 1 if the type is valid, based on a predefined set of valid types, and 0 if it's not.
 *
 * @param type The DNS resource record type as an unsigned short.
 * @return 1 if the type is valid, 0 otherwise.
 */
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

/**
 * @brief Check if a DNS class is valid.
 *
 * This function determines whether a DNS class, represented as an unsigned short 'type',
 * is valid or not. It returns 1 if the class is valid (IN, CS, CH, or HS) and 0 if it is
 * not valid.
 *
 * @param type The DNS class as an unsigned short.
 * @return 1 if the class is valid, 0 otherwise.
 */
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

/**
 * @brief Get the DNS class as a string.
 *
 * This function takes a DNS class represented as an unsigned short 'class' and returns a
 * string representation of the class. If the provided class is not valid, it returns
 * "Not supported."
 *
 * @param class The DNS class as an unsigned short.
 * @return A string representing the DNS class or "Not supported" for invalid classes.
 */
const char* get_dns_class(unsigned short class) {
    if(!is_class_valid(class))
        return "Not supported";

    return class_names[class];
}

/**
 * @brief Get the DNS type as a string.
 *
 * This function takes a DNS type represented as an unsigned short 'type' and returns a
 * string representation of the type. If the provided type is not valid, it returns
 * "Not supported."
 *
 * @param type The DNS type as an unsigned short.
 * @return A string representing the DNS type or "Not supported" for invalid types.
 */
const char* get_dns_type(unsigned short type) {
    if(!is_type_valid(type))
        return "Not supported";

    return type_names[type];
}

/**
 * @brief Print the contents of a binary packet in a human-readable format.
 *
 * NOTE: This function is only for debugging purposes. It may not be used in the actual code.
 *
 * This function takes a binary 'packet' and its 'len', and prints its contents in a
 * human-readable format, showing hexadecimal values and ASCII characters. The output
 * is formatted with columns for better readability.
 *
 * @param packet The binary packet to print.
 * @param len The length of the packet.
 */
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

/**
 * @brief Convert a boolean value to "Yes" or "No" string.
 *
 * This function takes a boolean 'value' and returns "Yes" if the value is true (non-zero)
 * and "No" if the value is false (zero). It provides a convenient way to convert boolean
 * values to human-readable strings.
 *
 * @param value The boolean value to convert.
 * @return "Yes" if 'value' is true, "No" if 'value' is false.
 */
const char* bool_to_yes_no(int value) {
    return value ? "Yes" : "No";
}

/**
 * @brief Get the length of a domain name in the DNS packet.
 *
 * This function calculates the length of a domain name located at the specified
 * 'pointer_to_name' in the DNS packet. If the name uses compression, it returns 2,
 * indicating that it's a pointer to another location in the packet. Otherwise, it
 * returns the length of the name plus 1 to account for the null terminator.
 *
 * @param pointer_to_name Pointer to the location of the domain name in the DNS packet.
 * @param name The domain name to calculate the length for (if not using compression).
 * @return The length of the domain name or 2 if it's a pointer to another location.
 */
int get_name_length(unsigned char* pointer_to_name, char* name) {
    return (*pointer_to_name & 192) == 192 ? 2 : strlen(name) + 1;
}
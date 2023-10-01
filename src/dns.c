#define _POSIX_C_SOURCE 200112L
#include "dns.h"

#define YES "Yes"
#define NO "No"
#define A "A"
#define AAAA "AAAA"

#define IN "IN"
#define CNAME "CNAME"

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

void dns_query(args_t* args, unsigned char* query, char* domain);
const char* get_rr_class(unsigned short type);
const char* get_rr_records(unsigned short type);
void print_packet(unsigned char* packet, int len);
void parse_domain_name(unsigned char* packet, unsigned char* buffer, char* result);

void log_dns_header(dns_header_t*);
void error(err_t);

void error(err_t err) {
    perror("Error arguments");
    exit(err);
}

const char* get_rr_class(unsigned short class) {
    switch (htons(class)) {
    case 1:
        return IN;
    }
    return "";
}

const char* get_rr_records(unsigned short type) {
    switch (htons(type)) {
    case 1:
        return A;

    case 5:
        return CNAME;

    case 28:
        return AAAA;
    }

    return "";
}

int main(int argc, char** argv) {

    int sock;
    int err;

    args_t args;

    err = getopts(&args, argc, argv);
    if (err) {
        error(err);
    }

    const int ai_family = get_ai_family(&args);

    struct addrinfo hints, * res;
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_DGRAM; 

    err = getaddrinfo(args.source_addr, args.port, &hints, &res);
    if (err) {
        if (err == EAI_SYSTEM)
            fprintf(stderr, "looking up www.example.com: %s\n", strerror(errno));
        else
            fprintf(stderr, "looking up www.example.com: %s\n", gai_strerror(err));
        return -1;
    }

    char ip[args.ipv6 ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN];

    if (res->ai_family == AF_INET6) {
        struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)res->ai_addr;
        inet_ntop(AF_INET6, &(ipv6->sin6_addr), ip, INET6_ADDRSTRLEN);
    }
    else if (res->ai_family == AF_INET) {
        struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
        inet_ntop(AF_INET, &(ipv4->sin_addr), ip, INET_ADDRSTRLEN);
    }
    else {
        // Handle an unsupported address family (if necessary)
        fprintf(stderr, "Unsupported address family\n");
        return -1;
    }

    printf("%s\n", ip);

    if ((sock = socket(ai_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        perror("Socket creation failed");
        return 1;
    }
    
    struct sockaddr_in6 server;
    server.sin6_family = ai_family;
    server.sin6_port = htons(53);
    inet_pton(ai_family, ip, &server.sin6_addr);

    unsigned char query[65536] = { 0 };
    dns_query(&args, query, args.target_addr);

    int qlen = (sizeof(dns_header_t) + (strlen((char*)&query[sizeof(dns_header_t)]) + 1) + sizeof(dns_question_t));

    if (sendto(sock, query, qlen, 0, (struct sockaddr*)&server, sizeof(server)) == -1) {
        perror("DNS query sendto failed");
        exit(1);
    }

    // Buffer to store received data
    unsigned char buffer[65536] = { 0 }; // Adjust the buffer size as needed

    int addr_len = sizeof server;
    ssize_t bytes_received = recvfrom(sock, buffer, 65536, 0, (struct sockaddr*)&server, (socklen_t*)&addr_len);
    if (bytes_received == -1) {
        perror("recvfrom");
        return 1;
    }

    // Extract the DNS header
    dns_header_t* dns_header = (dns_header_t*)buffer;
    print_packet(buffer, bytes_received);
    // log_dns_header(dns_header);

    // Calculate the offset to the answer section
    unsigned char* qname = (unsigned char*)&buffer[sizeof(dns_header_t)];
    dns_question_t* dns_question = (dns_question_t*)&buffer[sizeof(dns_header_t) + strlen((char*)qname) + 1];

    unsigned char* pointer = (unsigned char*)&buffer[qlen];

    printf("Authoritative: %s, Recursive: %s, Truncated: %s\n", dns_header->aa ? YES : NO, dns_header->rd ? YES : NO, dns_header->tc ? YES : NO);
    printf("Question section (%d)\n", htons(dns_header->qdcount));
    printf(" %s, %s, %s\n", args.target_addr, htons(dns_question->qclass) == 1 ? A : AAAA, htons(dns_question->qtype) == 1 ? IN : "");
    printf("Answer section (%d)\n", htons(dns_header->ancount));
    
    for (int i = 0; i < ntohs(dns_header->ancount); i++) {
        // Parse the name in the answer section
        char name[256] = { 0 };

        parse_domain_name(pointer, buffer, name);
        dns_rr_t* dns_rr = (dns_rr_t*)(pointer + sizeof(short));

        // Handle different types of resource records
        if (ntohs(dns_rr->type) == 1) { // A record
            // Extract IPv4 address 
            struct in_addr ipv4_addr;
            memcpy(&ipv4_addr, pointer + sizeof(dns_rr_t), sizeof(struct in_addr));
            char ip_address[args.ipv6 ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ipv4_addr, ip_address, args.ipv6 ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN);
            printf(" %s, %s, %s, %d, %s\n", name, get_rr_records(dns_rr->type), get_rr_class(dns_rr->class), ntohl(dns_rr->ttl), ip_address);
        }
        else if (ntohs(dns_rr->type) == 5) { // CNAME record
            // Extract CNAME data
            char cname[256];
            parse_domain_name(pointer + sizeof(dns_rr_t), buffer, cname);
            printf(" %s, %s, %s, %d, %s\n", name, get_rr_records(dns_rr->type), get_rr_class(dns_rr->class), ntohl(dns_rr->ttl), cname);
        }

        pointer += sizeof(dns_rr_t) + ntohs(dns_rr->data_len);
    }
    printf("Authority section (%d)\n", htons(dns_header->nscount));
    printf("Additional section (%d)\n", htons(dns_header->arcount));

    freeaddrinfo(res);
    close(sock);

    return 0;
}

void parse_domain_name(unsigned char* rdata, unsigned char* buffer, char* result) {
    unsigned int position = 0;
    unsigned int len;

    while (1) {
        len = rdata[position++];

        // End of the domain name
        if (len == 0) {
            break;
        }
        
        // Check for message compression (The first two bits are ones)
        // 11XX XXXX & 1100 0000 == 1100 0000
        if ((len & 192) == 192) {
            // A pointer to another location in the packet
            unsigned int offset = rdata[position++];
            // Recursively parse the domain name at the offset
            parse_domain_name(buffer + offset, buffer, result);
            return;
        }
        else {
            for (int i = 0; i < (int)len; i++) {
                result[strlen(result)] = rdata[position++];
            }
            result[strlen(result)] = '.';
        }
    }
}

void format(unsigned char* dest, char* src, int len);
void format_hostname(unsigned char* dest, char* src);

void format(unsigned char* dest, char* src, int len) {
    if (*src == 0) {
        return;
    }

    if (*src == '.') {
        *(dest - len - 1) = len;
        format(dest + 1, src + 1, 0);
    }
    else {
        *dest = *src;
        format(dest + 1, src + 1, len + 1);
    }
}

void format_hostname(unsigned char* dest, char* src) {
    strcat((char*)src, ".");
    format(dest + 1, src, 0);
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

void dns_query(args_t* args ,unsigned char* query, char* domain) {
    dns_header_t dns_header = {
        .id = htons(getpid()),      // Set the ID to X (you can change this value)
        .qr = 0,                    // Query (0) or Response (1)
        .opcode = 0,                // Standard query (0)
        .aa = 0,                    // Authoritative (0)
        .tc = 0,                    // Truncated (0)
        .rd = args->recursive,      // Recursion Desired (X)
        .ra = 0,                    // Recursion Available (0)
        .z = 0,                     // Reserved, set to 0
        .cd = 0,
        .ad = 0,
        .rcode = 0,                 // Response code, set to 0 for a query
        .qdcount = htons(1),        // Number of questions, in network byte order
        .ancount = 0,               // Number of answers, set to 0 for a query
        .nscount = 0,               // Number of authority records, set to 0 for a query
        .arcount = 0                // Number of additional records, set to 0 for a query
    };

    // Combine header and question into the final query packet
    memcpy(query, &dns_header, sizeof(dns_header));

    unsigned char* qname = (unsigned char*)&query[sizeof(dns_header_t)];

    // TODO add formatting for Ipv6
    format_hostname(qname, domain);

    int len = strlen((char*)qname);

    dns_question_t* qinfo = (dns_question_t*)&query[(sizeof(dns_header_t) + len + 1)];
    qinfo->qtype = htons(args->ipv6 ? 28 : 1); // TODO Set 5 to test CNAME
    qinfo->qclass = htons(1);

}
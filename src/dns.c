#define _POSIX_C_SOURCE 200112L
#include "dns.h"

#define YES "Yes"
#define NO "No"
#define A "A"
#define AAAA "AAAA"

#define IN "IN"
#define CNAME "CNAME"

#define IPV6 (args.ipv6)
#define IPV4 (!args.ipv6)
#define AI_FAMILY (IPV6 ? AF_INET6 : AF_INET)
#define ADDRSTRLEN (IPV6 ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN)

#define MAX_BUFF 65536



void dns_query(args_t* args, unsigned char* query, char* domain);
const char* get_rr_class(unsigned short type);
const char* get_rr_records(unsigned short type);
void parse_domain_name(unsigned char* packet, unsigned char* buffer, char* result);

void exit_error(err_t, const char* message);

void compress(unsigned char* dest, char* src, int len);
void compress_domain_name(unsigned char* dest, char* src);

void send_dns_query(int ai_family,unsigned char* buffer, unsigned char* query, char* addr, int qlen);

const char* get_rr_class(unsigned short class) {
    switch (htons(class)) {
    case 1:
        return "IN";
    }
    return "";
}

const char* get_rr_records(unsigned short raw_type) {
    int type = htons(raw_type);

    if(type < MIN_TYPE || type > MAX_TYPE){
        return ""; // TODO should here be error?
    }

    return type_names[type];
}

int main(int argc, char** argv) {

    args_t args; // 
    int err = 0; //

    getopts(&args, argc, argv);

    char ip[ADDRSTRLEN];
    unsigned char query[MAX_BUFF] = { 0 };

    struct addrinfo hints, *res;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    err = getaddrinfo(args.source_addr, args.port, &hints, &res);
    if (err) {
        if (err == EAI_SYSTEM)
            fprintf(stderr, "looking up www.example.com: %s\n", strerror(errno));
        else
            fprintf(stderr, "looking up www.example.com: %s\n", gai_strerror(err));
        return -1;
    }

    if (res->ai_family == AF_INET6) {
        struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)res->ai_addr;
        inet_ntop(AF_INET6, &(ipv6->sin6_addr), ip, INET6_ADDRSTRLEN);
    }
    else if (res->ai_family == AF_INET) {
        struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
        inet_ntop(AF_INET, &(ipv4->sin_addr), ip, INET_ADDRSTRLEN);
    }
    else {
        fprintf(stderr, "Unsupported address family\n");
        return -1;
    }

    dns_query(&args, query, args.target_addr);

    const int dns_header_size = sizeof(dns_header_t);
    const int dns_question_size = sizeof(dns_question_t);
    const int qname_size = (strlen((char*)(query + dns_header_size)) + 1);
    const int query_size = (dns_header_size + qname_size + dns_question_size);


    // Buffer to store received data
    unsigned char buffer[MAX_BUFF] = { 0 };

    send_dns_query(res->ai_family, buffer, query, ip, query_size);


    // Extract the DNS header
    dns_header_t* dns_header = (dns_header_t*)buffer;

    dns_question_t* dns_question = (dns_question_t*)(buffer + dns_header_size + qname_size);

    unsigned char* pointer = (unsigned char*)(buffer + query_size);

    printf("Authoritative: %s, Recursive: %s, Truncated: %s\n", dns_header->aa ? YES : NO, dns_header->rd ? YES : NO, dns_header->tc ? YES : NO);
    printf("Question section (%d)\n", htons(dns_header->qdcount));
    printf(" %s, %s, %s\n", args.target_addr, get_rr_records(dns_question->qtype), get_rr_class(dns_question->qclass));
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
            char ip_address[ADDRSTRLEN];
            inet_ntop(AF_INET, &ipv4_addr, ip_address, ADDRSTRLEN);
            printf(" %s, %s, %s, %d, %s\n", name, get_rr_records(dns_rr->type), get_rr_class(dns_rr->class), ntohl(dns_rr->ttl), ip_address);
        }
        else if (ntohs(dns_rr->type) == 5) { // CNAME record
            // Extract CNAME data
            char cname[256];
            parse_domain_name(pointer + sizeof(dns_rr_t), buffer, cname);
            printf(" %s, %s, %s, %d, %s\n", name, get_rr_records(dns_rr->type), get_rr_class(dns_rr->class), ntohl(dns_rr->ttl), cname);
        }
        else if (ntohs(dns_rr->type) == 28) {
            struct in6_addr ipv6_addr;
            memcpy(&ipv6_addr, pointer + sizeof(dns_rr_t), sizeof(struct in6_addr));
            char ip_address[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ipv6_addr, ip_address, INET6_ADDRSTRLEN);
            printf(" %s, %s, %s, %d, %s\n", name, get_rr_records(dns_rr->type), get_rr_class(dns_rr->class), ntohl(dns_rr->ttl), ip_address);
        }

        pointer += sizeof(dns_rr_t) + ntohs(dns_rr->data_len);
    }
    printf("Authority section (%d)\n", htons(dns_header->nscount));
    for (int i = 0; i < ntohs(dns_header->nscount); i++) {
        // Parse the name in the answer section
        char name[256] = { 0 };
        parse_domain_name(pointer, buffer, name);
        dns_rr_t* dns_rr = (dns_rr_t*)(pointer + sizeof(short));

        // Handle different types of resource records
        if (ntohs(dns_rr->type) == 6) { // A record
            // Extract IPv4 address 
            struct in_addr ipv4_addr;
            memcpy(&ipv4_addr, pointer + sizeof(dns_rr_t), sizeof(struct in_addr));
            char ip_address[ADDRSTRLEN];
            inet_ntop(AF_INET, &ipv4_addr, ip_address, ADDRSTRLEN);
            printf(" %s, %s, %s, %d, %s\n", name, get_rr_records(dns_rr->type), get_rr_class(dns_rr->class), ntohl(dns_rr->ttl), ip_address);
        }

        pointer += sizeof(dns_rr_t) + ntohs(dns_rr->data_len);
    }
    printf("Additional section (%d)\n", htons(dns_header->arcount));

    freeaddrinfo(res);

    return 0;
}

// TODO add port
void send_dns_query(int ai_family, unsigned char* buffer, unsigned char* query, char* addr, int qlen){
    int sockt;
    int err;
    socklen_t addr_len;
    ssize_t bytes_received;

    struct sockaddr_storage server;

    memset(&server, 0, sizeof(server));

    if(ai_family == AF_INET){
        struct sockaddr_in* server4 = (struct sockaddr_in*)&server;
        server4->sin_family = AF_INET;
        server4->sin_port = htons(53);
        inet_ntop(AF_INET, &server4->sin_addr, (char*)addr, INET_ADDRSTRLEN);
    } else {
        struct sockaddr_in6* server6 = (struct sockaddr_in6*)&server;
        server6->sin6_family = AF_INET6;
        server6->sin6_port = htons(53);
        inet_pton(AF_INET6, (char*)addr, &server6->sin6_addr);
    }

    sockt = socket(ai_family, SOCK_DGRAM, IPPROTO_UDP);
    if (sockt == -1) {
        close(sockt);
        exit_error(1, "Socket creation failed");
    }

    err = sendto(sockt, query, qlen, 0, (struct sockaddr*)&server, sizeof(server));
    if (err == -1) {
        close(sockt);
        exit_error(1, "DNS query sendto failed");
    }

    addr_len = sizeof server;
    bytes_received = recvfrom(sockt, buffer, MAX_BUFF, 0, (struct sockaddr*)&server, &addr_len);
    if (bytes_received == -1) {
        close(sockt);
        exit_error(1, "recvfrom");
    }

    close(sockt);
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

void compress(unsigned char* dest, char* src, int len) {
    if (*src == 0) {
        return;
    }

    if (*src == '.') {
        *(dest - len - 1) = len;
        compress(dest + 1, src + 1, 0);
    }
    else {
        *dest = *src;
        compress(dest + 1, src + 1, len + 1);
    }
}

void compress_domain_name(unsigned char* dest, char* src) {
    strcat((char*)src, ".");
    compress(dest + 1, src, 0);
}

void dns_query(args_t* args, unsigned char* query, char* domain) {
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

    unsigned char* qname = (unsigned char*)(query + sizeof(dns_header_t));

    compress_domain_name(qname, domain);

    int len = strlen((char*)qname);

    dns_question_t* qinfo = (dns_question_t*)(query + sizeof(dns_header_t) + len + 1);
    qinfo->qtype = htons(args->ipv6 ? 28 : 1); // TODO Set 5 to test CNAME
    qinfo->qclass = htons(1);

}
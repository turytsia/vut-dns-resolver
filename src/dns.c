#define _POSIX_C_SOURCE 200112L
#include "dns.h"

#define YES "Yes"
#define NO "No"

#define IPV6 (args.ipv6)
#define IPV4 (!args.ipv6)
#define ADDRSTRLEN (IPV6 ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN)

#define MAX_BUFF 65536

const char* get_dns_class(unsigned short type);
const char* get_dns_type(unsigned short type);
void parse_domain_name(unsigned char* packet, unsigned char* buffer, char* result);
void create_dns_query(args_t* args, unsigned char* query, char* domain);
void send_dns_query(int ai_family, unsigned char* buffer, unsigned char* query, char* addr, int qlen);
void compress(unsigned char* dest, char* src, int len);
void compress_domain_name(unsigned char* dest, char* src);
void print_rr(unsigned char* pointer, unsigned char* buffer, int n);
void print_packet(unsigned char* packet, int len);
void create_dns_reverse_query(args_t* args, unsigned char* query, char* domain);

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
// TODO Avoid DNSSEC
// TODO 
int main(int argc, char** argv) {

    args_t args; // 
    int err = 0; //

    getopts(&args, argc, argv);

    char ip[ADDRSTRLEN];
    unsigned char query[MAX_BUFF] = { 0 };

    struct addrinfo hints, * res;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    err = getaddrinfo(args.source_addr, args.port, &hints, &res);
    if (err) {
        if (err == EAI_SYSTEM)
            exit_error(1, strerror(errno));
        else
            exit_error(1, gai_strerror(err));
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
        exit_error(1, "Unsupported address family");
    }

    if (args.reverse) {
        create_dns_reverse_query(&args, query, args.target_addr);
    }
    else {
        create_dns_query(&args, query, args.target_addr);
    }

    const int dns_header_size = sizeof(dns_header_t);
    const int dns_question_size = sizeof(dns_question_t);
    const int qname_size = (strlen((char*)(query + dns_header_size)) + 1);
    const int query_size = (dns_header_size + qname_size + dns_question_size);
    // printf("%d\n", qname_size);
    // const int query_size = (dns_header_size + qname_size + sizeof(dns_rr_t) + 15);

    print_packet(query, query_size);

    // Buffer to store received data
    unsigned char buffer[MAX_BUFF] = { 0 };

    send_dns_query(res->ai_family, buffer, query, ip, query_size);

    freeaddrinfo(res);


    // Extract the DNS header
    dns_header_t* dns_header = (dns_header_t*)buffer;

    dns_question_t* dns_question = (dns_question_t*)(buffer + dns_header_size + qname_size);

    unsigned char* pointer = (unsigned char*)(buffer + query_size);

    printf("Authoritative: %s, Recursive: %s, Truncated: %s\n", dns_header->aa ? YES : NO, dns_header->rd ? YES : NO, dns_header->tc ? YES : NO);
    printf("Question section (%d)\n", htons(dns_header->qdcount));
    
    printf(" %s, %s, %s\n", args.target_addr, get_dns_type(dns_question->qtype), get_dns_class(dns_question->qclass));

    printf("Answer section (%d)\n", htons(dns_header->ancount));
    print_rr(pointer, buffer, htons(dns_header->ancount));
    
    printf("Authority section (%d)\n", htons(dns_header->nscount));
    print_rr(pointer, buffer, htons(dns_header->nscount));

    printf("Additional section (%d)\n", htons(dns_header->arcount));
    print_rr(pointer, buffer, htons(dns_header->arcount));

    return 0;
}

const char* get_dns_class(unsigned short class) {
    return class_names[htons(class)];
}

const char* get_dns_type(unsigned short raw_type) {
    return type_names[htons(raw_type)];
}

void print_rr(unsigned char* pointer, unsigned char* buffer, int n) {
    for (int i = 0; i < n; i++) {
        // Parse the name in the answer section
        char name[256] = { 0 };
        dns_rr_t* dns_rr = (dns_rr_t*)(pointer + sizeof(short));
        parse_domain_name(pointer, buffer, name);

        printf(" %s, %s, %s, %d, ", name, get_dns_type(dns_rr->type), get_dns_class(dns_rr->class), ntohl(dns_rr->ttl));

        switch (ntohs(dns_rr->type)) {
        case A:{
            // Extract IPv4 address 
            struct in_addr ipv4_addr;
            memcpy(&ipv4_addr, pointer + sizeof(dns_rr_t), sizeof(struct in_addr));
            char ip_address[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ipv4_addr, ip_address, INET_ADDRSTRLEN);
            printf("%s\n", ip_address);
            break;
        }
        case CNAME:{
            // Extract CNAME data
            char cname[256] = { 0 };
            parse_domain_name(pointer + sizeof(dns_rr_t), buffer, cname);
            printf("%s\n", cname);
            break;
        }
        case AAAA:{
            struct in6_addr ipv6_addr;
            memcpy(&ipv6_addr, pointer + sizeof(dns_rr_t), sizeof(struct in6_addr));
            char ip_address[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ipv6_addr, ip_address, INET6_ADDRSTRLEN);
            printf("%s\n", ip_address);
            break;
        }
        default:
            printf(" %s is not supported yet.\n", get_dns_type(ntohs(dns_rr->type)));
        }

        pointer += sizeof(dns_rr_t) + ntohs(dns_rr->data_len);
    }
}

// TODO add port
void send_dns_query(int ai_family, unsigned char* buffer, unsigned char* query, char* addr, int qlen) {
    int sockt;
    int err;
    socklen_t addr_len;
    ssize_t bytes_received;

    struct sockaddr_storage server;

    memset(&server, 0, sizeof(server));

    if (ai_family == AF_INET) {
        struct sockaddr_in* server4 = (struct sockaddr_in*)&server;
        server4->sin_family = AF_INET;
        server4->sin_port = htons(53);
        inet_ntop(AF_INET, &server4->sin_addr, (char*)addr, INET_ADDRSTRLEN);
    }
    else {
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

    print_packet(buffer, bytes_received);

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

void create_dns_query(args_t* args, unsigned char* query, char* domain) {
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
    qinfo->qtype = htons(args->ipv6 ? AAAA : args->reverse ? PTR : A); // TODO Set 5 to test CNAME
    qinfo->qclass = htons(1);

}

void create_dns_reverse_query(args_t* args, unsigned char* query, char* domain) {
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

    for (char* token = strtok(domain, "."); token != NULL; token = strtok(NULL, ".")) {
        char buf[MAX_BUFF] = { 0 };

        strcpy(buf, (char*)qname);
        if (*buf != 0) {
            sprintf((char*)qname, "%s.%s", token, buf);
        }
        else {
            sprintf((char*)qname, "%s.", token);
        }
    }

    char buf[MAX_BUFF] = { 0 };


    strcat((char*)qname, "IN-ADDR.ARPA");

    printf("%s\n", qname);

    compress_domain_name((unsigned char*)buf, (char*)qname);

    strcpy((char*)qname, buf);

    for (int i = 0; i < (int)strlen((char*)qname); i++) {
        printf("%d ", qname[i]);
    }

    printf("%s\n", qname);

    int len = strlen((char*)qname);

    dns_question_t* qinfo = (dns_question_t*)(qname + len + 1);
    qinfo->qtype = htons(PTR); 
    qinfo->qclass = htons(1); 
}

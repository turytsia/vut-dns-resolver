#include "dns.h"

int main(int argc, char** argv) {

    args_t args;

    memset(&args, 0, sizeof(args_t));   // Reset args

    getopts(&args, argc, argv);         // Read and validate program arguments

    int err = 0;                        // Error checking variable

    struct addrinfo hints, *res;        // Hints and result list for getaddrinfo

    memset(&hints, 0, sizeof(struct addrinfo));   // Reset hints
    hints.ai_family = AF_UNSPEC;        // Allow IPV6 or IPV4
    hints.ai_socktype = SOCK_DGRAM;     // UDP

    // Get ip address of a specified dns server
    err = getaddrinfo(args.source_addr, args.port, &hints, &res);
    if (err) {
        if (err == EAI_SYSTEM){
            exit_error(1, strerror(errno));
        }
        else{
            exit_error(1, gai_strerror(err));
        }
    }

    // Buffer for ip address of a specified dns server
    char dns_addr[args.ipv6 ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN];

    // Save ip address of a dns server into the buffer
    if (res->ai_family == AF_INET6) {
        struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)res->ai_addr;
        inet_ntop(AF_INET6, &(ipv6->sin6_addr), dns_addr, INET6_ADDRSTRLEN);
    }
    else if (res->ai_family == AF_INET) {
        struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
        inet_ntop(AF_INET, &(ipv4->sin_addr), dns_addr, INET_ADDRSTRLEN);
    }
    else {
        exit_error(1, "Unsupported address family");
    }

    // Dns query buffer
    unsigned char query[MAX_BUFF] = { 0 };

    // Construct DNS query and save it into the buffer
    create_dns_query(&args, query);

    const int dns_header_size = sizeof(dns_header_t);
    const int dns_question_size = sizeof(dns_question_t);
    const int qname_size = (strlen(((char*)query + dns_header_size)) + 1);
    const int query_size = (dns_header_size + qname_size + dns_question_size);

    // LOG packet
    // print_packet(query, query_size);

    // Buffer to store received data
    unsigned char buffer[MAX_BUFF] = { 0 };

    send_dns_query(res->ai_family, buffer, query, dns_addr, query_size);

    // Clean up getaddrinfo
    freeaddrinfo(res);

    // Extract the DNS header
    dns_header_t* dns_header = (dns_header_t*)buffer;
    
    // TODO validate RCODE
    printf("%d\n", dns_header->rcode);

    // Extract the DNS question
    dns_question_t* dns_question = (dns_question_t*)(buffer + dns_header_size + qname_size);

    unsigned short qtype = ntohs(dns_question->qtype);
    unsigned short qclass = ntohs(dns_question->qclass);

    // Set pointer to QNAME
    unsigned char* pointer = (unsigned char*)(buffer + dns_header_size);

    printf("Authoritative: %s, Recursive: %s, Truncated: %s\n",  bool_to_yes_no(dns_header->aa), bool_to_yes_no(dns_header->rd), bool_to_yes_no(dns_header->tc));
    printf("Question section (%d)\n", htons(dns_header->qdcount));

    char qname[MAX_BUFF] = {0};

    parse_domain_name(pointer, buffer, qname);

    printf(" %s, %s, %s\n", qname, get_dns_type(qtype), get_dns_class(qclass));

    pointer += qname_size + dns_question_size;

    printf("Answer section (%d)\n", htons(dns_header->ancount));
    print_rr(pointer, buffer, htons(dns_header->ancount));

    printf("Authority section (%d)\n", htons(dns_header->nscount));
    print_rr(pointer, buffer, htons(dns_header->nscount));

    printf("Additional section (%d)\n", htons(dns_header->arcount));
    print_rr(pointer, buffer, htons(dns_header->arcount));

    return 0;
}

void print_rr(unsigned char* pointer, unsigned char* buffer, int n) {
    for (int i = 0; i < n; i++) {
        // Parse the name in the answer section
        int len;
        char name[256] = { 0 };

        parse_domain_name(pointer, buffer, name);

        // printf("%s\n", name);

        if ((*pointer & 192) == 192) {
            // Compression: The domain name is a pointer
            len = 2; // A pointer is 2 bytes long
        } else {
            // Regular Label: The domain name is not compressed
            len = strlen(name) + 1;
        }

        dns_rr_t* dns_rr = (dns_rr_t*)(pointer + len);

        unsigned short rr_type = ntohs(dns_rr->type);
        unsigned short rr_class = ntohs(dns_rr->class);
        unsigned int rr_ttl = ntohl(dns_rr->ttl);

        // printf("%d\n", rr_type);
        // printf("%d\n", rr_class);
        // printf("%d\n", ntohs(dns_rr->rdlength));

        printf(" %s, %s, %s, %d, ", name, get_dns_type(rr_type), get_dns_class(rr_class), rr_ttl);

        switch (rr_type) {
            case A:
                print_ipv4_data(pointer + len);
                break;
            case CNAME:
            case PTR:
                print_domain_name_data(pointer + len, buffer);
                break;
            case AAAA:
                print_ipv6_data(pointer + len);
                break;
            case SOA:
                print_soa_data(((unsigned char*)dns_rr + sizeof(dns_rr_t)), buffer);
                break;
            default:
                printf("%s is not supported yet.\n", get_dns_type(rr_type));
        }

        pointer +=  len + sizeof(dns_rr_t) + ntohs(dns_rr->rdlength);

    }
}

void print_ipv4_data(unsigned char* pointer) {
    struct in_addr ipv4_addr;
    memcpy(&ipv4_addr, pointer + sizeof(dns_rr_t), sizeof(struct in_addr));
    char ip_address[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ipv4_addr, ip_address, INET_ADDRSTRLEN);
    printf("%s\n", ip_address);
}

void print_domain_name_data(unsigned char* pointer, unsigned char* buffer) {
    char data[256] = { 0 };
    parse_domain_name(pointer + sizeof(dns_rr_t), buffer, data);
    printf("%s\n", data);
}

void print_ipv6_data(unsigned char* pointer) {
    struct in6_addr ipv6_addr;
    memcpy(&ipv6_addr, pointer + sizeof(dns_rr_t), sizeof(struct in6_addr));
    char ip_address[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ipv6_addr, ip_address, INET6_ADDRSTRLEN);
    printf("%s\n", ip_address);
}

void print_soa_data(unsigned char* pointer, unsigned char* buffer) {
    char mname[256] = { 0 };
    char rname[256] = { 0 };

    int mname_len, rname_len;

    // printf("- %s\n", pointer - 135);

    parse_domain_name(pointer, buffer, mname);
    if ((*pointer & 192) == 192) {
        // Compression: The domain name is a pointer
        mname_len = 2; // A pointer is 2 bytes long
    }
    else {
        // Regular Label: The domain name is not compressed
        mname_len = strlen(mname) + 1;
    }

    parse_domain_name(pointer + mname_len, buffer, rname);
    if ((*(pointer + mname_len) & 192) == 192) {
        // Compression: The domain name is a pointer
        rname_len = 2; // A pointer is 2 bytes long
    }
    else {
        // Regular Label: The domain name is not compressed
        rname_len = strlen(rname) + 1;
    }
    // printf("- %d\n", mname_len);

    // printf("%s\n", rname);
    // printf("- %d\n", rname_len);

    dns_soa_t* soa = (dns_soa_t*)(pointer + mname_len + rname_len);

    printf("%s, %s, %d, %d, %d, %d, %d\n", mname, rname, ntohl(soa->serial), ntohl(soa->refresh), ntohl(soa->retry), ntohl(soa->expire), ntohl(soa->min_ttl));
}

// TODO add port
void send_dns_query(int ai_family, unsigned char* buffer, unsigned char* query, char* addr, int qlen) {
    int sockt;
    int err;
    socklen_t addr_len;
    ssize_t bytes_received;

    struct sockaddr_storage server;

    memset(&server, 0, sizeof(struct sockaddr_storage));

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

    err = sendto(sockt, query, qlen, 0, (struct sockaddr*)&server, sizeof(struct sockaddr_storage));
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

void create_dns_query(args_t* args, unsigned char* query) {
    dns_header_t dns_header = {
        .id = htons(getpid()),      // Set the ID to X (you can change this value)
        .qr = 0,                    // Query (0)
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
    memcpy(query, &dns_header, sizeof(dns_header_t));
    
    unsigned char* qname = (unsigned char*)(query + sizeof(dns_header_t));
    unsigned char qbuffer[MAX_BUFF] = {0};

    if(args->reverse) {
        // TODO here could be ipv6
        reverse_dns_ipv4((char*)qbuffer, args->target_addr);
    } else {
        strcpy((char*)qbuffer, args->target_addr);
    }

    compress_domain_name(qname, (char*)qbuffer);

    int len = strlen((char*)qname);

    dns_question_t* qinfo = (dns_question_t*)(qname + len + 1);
    // TODO refactor
    qinfo->qtype = htons(args->ipv6 ? AAAA : args->reverse ? PTR : A);
    qinfo->qclass = htons(1);

}

void reverse_dns_ipv4(char* dest, char* addr) {
    for (char* token = strtok(addr, "."); token != NULL; token = strtok(NULL, ".")) {
        char buf[MAX_BUFF] = { 0 };

        strcpy(buf, (char*)dest);
        if (*buf != 0) {
            sprintf((char*)dest, "%s.%s", token, buf);
        }
        else {
            sprintf((char*)dest, "%s.", token);
        }
    }

    strcat((char*)dest, "in-addr.arpa");
}

// void reverse_dns_ipv6(char* dest, char* addr){
//     // TODO 
// }
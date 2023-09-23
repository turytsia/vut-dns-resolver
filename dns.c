#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
    unsigned short id;
    unsigned char qr : 1;
    unsigned char opcode : 4;
    unsigned char aa : 1;
    unsigned char tc : 1;
    unsigned char rd : 1;
    unsigned char ra : 1;
    unsigned char z : 1;
    unsigned char rcode : 4;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
} dns_header_t;

typedef struct {
    int recursive;
    int reverse;
    int ipv6;
    int port;
    char source_addr[255];
    char target_addr[255];
} args_t;

int getopts(args_t*, int, char**);

void dns_query(unsigned char* query, char* domain) {
    dns_header_t dns_header = {
        .id = 0x1234,               // Set the ID to 0x1234 (you can change this value)
        .qr = 0,                    // Query (0) or Response (1)
        .opcode = 0,                // Standard query (0)
        .aa = 0,                    // Not authoritative (0)
        .tc = 0,                    // Not truncated (0)
        .rd = 0,                    // Recursion Desired (1)
        .ra = 0,                    // Recursion Available (0)
        .z = 0,                     // Reserved, set to 0
        .rcode = 0,                 // Response code, set to 0 for a query
        .qdcount = htons(1),        // Number of questions, in network byte order
        .ancount = 0,               // Number of answers, set to 0 for a query
        .nscount = 0,               // Number of authority records, set to 0 for a query
        .arcount = 0                // Number of additional records, set to 0 for a query
    };

    unsigned char* qname = (unsigned char*)(query + sizeof(dns_header_t));

    strcpy((char*)qname, domain);

    int len = strlen((char*)qname);
    qname[len] = 0;

    unsigned short* qtype = (unsigned short*)(qname + len + 1);
    *qtype = htons(1); // A record (IPv4 address)

    // Combine header and question into the final query packet
    memcpy(query, &dns_header, sizeof(dns_header));

}

int main(int argc, char** argv) {

    args_t args = { .port = 53 };
    
    int err = getopts(&args, argc, argv);
    if (err) {
        perror("Error arguments");
        exit(1);
    }

    printf("Recursive: %d\n", args.recursive);
    printf("Reverse: %d\n", args.reverse);
    printf("Ipv6: %d\n", args.ipv6);
    printf("Port: %d\n", args.port);
    printf("Source IP: %s\n", args.source_addr);
    printf("Target IP: %s\n", args.target_addr);

    int sock;
    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        perror("Socket creation failed");
        exit(1);
    }

    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));

    server.sin_family = AF_INET;
    server.sin_port = htons(args.port);
    server.sin_addr.s_addr = inet_addr(args.target_addr);

    unsigned char query[sizeof(dns_header_t) + strlen(args.source_addr) + 2];
    dns_query(query, args.source_addr);


    if (sendto(sock, query, sizeof(dns_header_t) + strlen(args.source_addr) + 2, 0, (struct sockaddr*)&server, sizeof(server)) == -1) {
        perror("DNS query sendto failed");
        exit(1);
    }

    unsigned char response_buffer[512];
    socklen_t server_len = sizeof(server);
    int bytes_received = recvfrom(sock, response_buffer, sizeof(response_buffer), 0, (struct sockaddr*)&server, &server_len);
    if (bytes_received == -1) {
        perror("DNS response recvfrom failed");
        exit(1);
    }

    close(sock);
    
    return 0;
}

int getopts(args_t* args, int argc, char** argv) {

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0) {
            args->recursive = 1;
        }
        else if (strcmp(argv[i], "-6") == 0) {
            args->ipv6 = 1;
        }
        else if (strcmp(argv[i], "-x") == 0) {
            args->reverse = 1;
        }
        else if (strcmp(argv[i], "-s") == 0) {
            if (i + 1 >= argc) return 1;

            strcpy(args->source_addr, argv[++i]);
        }
        else if (strcmp(argv[i], "-p") == 0) {
            if (i + 1 >= argc) return 1;

            int port = atoi(argv[++i]);

            if (port == 0) return 1;

            args->port = port;
        }
        else if (i == argc - 1) {
            strcpy(args->target_addr, argv[i]);
        }
    }

    return 0;
}
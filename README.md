# DNS Resolver

**Author**: Oleksandr Turytsia <br />
**Created at**: 11/17/2023

A simple DNS resolver, implemented in C, that performs the task of translating human-readable domain names into IP addresses.

It supports such query types as `A`, `AAAA`, `PTR`. And response type `A`, `AAAA`, `PTR`, `CNAME` and `SOA`.

## Files
Source code for this project is located at `src/` folder. I should contain following files:
- args.c = Source file, that contains functions to parse input arguments
- args.h = Header file for `args.c`
- dns.c = Source file of a program. Main is located here.
- dns.h = Header file for `dns.h`
- error.c = Source file, that contains error handling function
- error.h = Header file for `error.c`
- libs.h = Header file with all the libs
- utils.c = Source file, that contains common functions for multiple source files
- utils.h = Header file for `utils.c`
 
## Prerequisites
Before using the DNS resolver, make sure you have the following prerequisites installed:
- GCC (Testing was done for the version 10.5.0)
- Unix-based system (Testing was done on FreeBSD)

## Installation
All the source code is located at src folder. Run following command in order to compile the project:
```bash
make
```

After the project is compiled, you can run following command to run a quick test:
```bash
./dns -r -s dns.google www.github.com
```

## Usage 
```bash
./dns [−r] [−x] [−h] [−t] [−6] −s server [−p port] address
```
- `-r`: Recursion Desired (Recursion Desired = 1), otherwise no recursion.
- `-6`: Query type AAAA instead of the default A.
- `-x`: Reverse query instead of direct query. Note, user can specify here ipv6 or ipv4 address without specifying `-6` option to make a reverse query.
- `-s server`: IP address or domain name of the server to which the query should be sent. Note, user can specify `server` by its domain or ipv6 address.
- `-p port`: The port number to send the query to, default is set to 53.
- `-h`: Display help info.
- `-t`: Enables testing mode (TTL is set to 0).
- `address`: The address to be queried

## Output
The program will construct dns query based on user’s input and send packet over udp to a specified dns server. Dns response may have following format:

```bash
Authoritative: Yes/No, Recursive: Yes/No, Truncated: Yes/No
Question section (1)
[ADDRESS], [QTYPE], [QCLASS]
Answer section (N)
[ADDRESS], [TYPE], [CLASS], [TTL], [RDATA]
...
Authority section (N)
[ADDRESS], [TYPE], [CLASS], [TTL], [RDATA]
...
Additional section (N)
[ ADDRESS ], [TYPE], [CLASS], [TTL], [RDATA]
...
```

First line displays response header flags (RD, TC, AA) followed by request response (RR) sections

## Error codes
DNS resolver is also suitable to be used as a part of a script, because it provides distinctive exit error codes, which can help potential programmers validate results

- Arguments parser error codes:
    - 1 - Unknown option
    - 2 - Invalid port
    - 3 - Port is missing
    - 4 - Source address is missing
    - 5 - Target address is missing
    - 6 - Option already specified
- Sending query error codes:
    - 10 - Socket creation error
    - 11 - Sending query error
    - 12 - Timeout
    - 13 - Recieving response error
- DNS header error codes (By subtracting 30 it is possible to get error
codes that correspond RFC 1035 documentation):
    - 31 - Format error
    - 32 - Server fail
    - 33 - Name error
    - 34 - Not implemented
    - 35 - Refused
- Other errors:
    - 20 - perror code
    - 21 - other errors
    - 22 - Family is not supported

## Bibliography

[RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035)
[RFC 3596](https://datatracker.ietf.org/doc/html/rfc3596)
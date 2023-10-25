# DNS Resolver

## Prerequisites
Before using the DNS resolver, make sure you have the following prerequisites installed:
- GCC (Tested version 10.5.0)
- Unix-based system (Tested on FreeBSD)

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
- `-x`: Reverse query instead of direct query.
- `-6`: Query type AAAA instead of the default A.
- `-s server`: IP address or domain name of the server to which the query should be sent.
- `-p port`: The port number to send the query to, default 53.
- `-h`: Display help info.
- `-t`: Enables testing mode (TTL is hidden).
- `address`: The address to be queried

# Output
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
[ ADDRESS ] , [ TYPE ] , [ CLASS ] , [ TTL ] , [ RDATA ]
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
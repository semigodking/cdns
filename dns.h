#ifndef DNS_H_SAT_OCT_08_13_56_39_2016
#define DNS_H_SAT_OCT_08_13_56_39_2016

#include <stdint.h>
#include <stdbool.h>
#ifdef __FreeBSD__
#include <sys/endian.h>
#else
#include <endian.h>
#endif

#define DNS_DEFAULT_PORT 53

#define DNS_RC_NOERROR   0
#define DNS_RC_FORMERR   1
#define DNS_RC_SERVFAIL  2
#define DNS_RC_NXDOMAIN  3
#define DNS_RC_NOTIMP    4
#define DNS_RC_REFUSED   5
#define DNS_RC_YXDOMAIN  6
#define DNS_RC_XRRSET    7
#define DNS_RC_NOTAUTH   8
#define DNS_RC_NOTZONE   9

// opcode in DNS header
#define OPCODE_QUERY     0
#define OPCODE_IQUERY    1
#define OPCODE_STATUS    2

// typical query types
#define QTYPE_A          1
#define QTYPE_NS         2
#define QTYPE_MD         3
#define QTYPE_MF         4
#define QTYPE_CNNAME     5
#define QTYPE_PTR       12
#define QTYPE_AAAA      28

// class of query
#define CLASS_IN         1

#define RCODE_BITS       4

#pragma pack(1)
/*
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
typedef struct dns_header_t {
    uint16_t id;
#if BYTE_ORDER == BIG_ENDIAN
    // Byte 3
    unsigned qr: 1;     /* response flag */
    unsigned opcode: 4; /* purpose of message */
    unsigned aa: 1;     /* authoritive answer */
    unsigned tc: 1;     /* truncated message */
    unsigned rd: 1;     /* recursion desired */
    // Byte 4
    unsigned ra: 1;     /* recursion available */
    unsigned z: 1;      /* reserved */
    unsigned ad: 1;
    unsigned cd: 1;
    unsigned rcode: 4;  /* response code */
#endif
#if BYTE_ORDER == LITTLE_ENDIAN || BYTE_ORDER == PDP_ENDIAN
    // Byte 3
    unsigned rd: 1;     /* recursion desired */
    unsigned tc: 1;     /* truncated message */
    unsigned aa: 1;     /* authoritive answer */
    unsigned opcode: 4; /* purpose of message */
    unsigned qr: 1;     /* response flag */
    // Byte 4
    unsigned rcode: 4;  /* response code */
    unsigned cd: 1;
    unsigned ad: 1;
    unsigned z: 1;      /* reserved */
    unsigned ra: 1;     /* recursion available */
#endif
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header;
#pragma pack()

void dns_init_query(struct dns_header_t * hdr);
uint16_t dns_set_id(struct dns_header_t * hdr, uint16_t id);
uint16_t dns_get_id(struct dns_header_t * hdr);
int dns_get_rcode(const char * rsp, size_t len);
size_t dns_append_edns_opt(char * buf, size_t len, size_t max_len);
const char * dns_get_answered_ip(const char * rsp, size_t len);
const char * dns_get_edns_opt(const char * rsp, size_t len);
uint16_t dns_get_edns_udp_payload_size(const char * rsp, size_t len);
bool dns_get_inet_qtype(const char * buf, size_t len, uint16_t * qtype);
size_t dns_build_a_query(char * buf, size_t size, const char * dn, int edns);
size_t dns_build_ptr_query(char * buf, size_t size, const char * dn, int edns);
int dns_validate_request(const char * req, size_t len);

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
#endif /* DNS_H_SAT_OCT_08_13_56_39_2016 */


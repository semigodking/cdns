#ifndef DNS_H_SAT_OCT_08_13_56_39_2016
#define DNS_H_SAT_OCT_08_13_56_39_2016

#include <sys/types.h>

#define DNS_DEFAULT_PORT 53

#define DNS_QR 0x80
#define DNS_TC 0x02
#define DNS_Z  0x40
#define DNS_RC_MASK      0x0F

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

#define QTYPE_A          1
#define QTYPE_NS         2
#define QTYPE_MD         3
#define QTYPE_MF         4
#define QTYPE_CNNAME     5

#define CLASS_IN         1

#pragma pack(1)
typedef struct dns_header_t {
    uint16_t id;
    uint8_t qr_opcode_aa_tc_rd;
    uint8_t ra_z_rcode;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header;
#pragma pack()

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
#endif /* DNS_H_SAT_OCT_08_13_56_39_2016 */


/* cdns - Cure DNS
 * Copyright (C) 2016 Zhuofei Wang <semigodking@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>
#include "dns.h"

static const char edns_opt[] = {
     0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EDNS OPT
};

static const char * _dns_skip_qname(const char * p)
{
    if (p) {
        while (*p != 0) {
            if ((*p & 0xC0) == 0xC0) {// compressed QNAME
                p += sizeof(uint16_t); // compressed QNAME has 1 addtional byte
                return p;
            }
            else
                p += (*(uint8_t *)p + 1);
        }
        p += 1;
    }
    return p;
}

static const char * _dns_skip_questions(uint16_t qdcount, const char * p)
{
    uint16_t i;
    // skip questions
    for (i = 0; i < qdcount; i++) {
        // skip QNAME
        p = _dns_skip_qname(p);
        // skip QTYPE
        p += sizeof(uint16_t);
        // skip QCLASS
        p += sizeof(uint16_t);
    }
    return p;
}

static const char * _dns_skip_resources(uint16_t count, const char * p)
{
    uint16_t i;
    // skip resources
    for (i = 0; i < count; i++) {
        // skip QNAME
        p = _dns_skip_qname(p);
        // QTYPE
        p += sizeof(uint16_t);
        // QCLASS
        p += sizeof(uint16_t);
        // TTL
        p += sizeof(uint32_t);
        // skip rdlength & rdata
        uint16_t rdlength = ntohs(*(uint16_t *)p);
        p += sizeof(uint16_t) + rdlength;
    }
    return p;
}

uint16_t dns_get_edns_udp_payload_size(const char * rsp, size_t len)
{
    const char * opt = dns_get_edns_opt(rsp, len);

    if (opt)
        return ntohs(*(uint16_t *)(opt 
                                   + 1                // NAME
                                   + sizeof(uint16_t) // OPT
                                  ));
    return 0;
}

const char * _dns_get_answered_ip(const char * rsp, size_t len, uint16_t qtype)
{
    struct dns_header_t * header = (struct dns_header_t *)rsp;
    const char * p = (const char *)header;
    uint16_t i;

    if (len <= sizeof(*header) || ntohs(header->ancount) == 0)
        return NULL;

    // skip header
    p += sizeof(*header);
    // skip questions
    p = _dns_skip_questions(ntohs(header->qdcount), p);
    // check answers
    for (i = 0; i < ntohs(header->ancount); i++) {
        // skip QNAME
        p = _dns_skip_qname(p);
        //  TYPE
        uint16_t qtype_ = ntohs(*(uint16_t *)p);
        p += sizeof(uint16_t);
        uint16_t qclass = ntohs(*(uint16_t *)p); 
        p += sizeof(uint16_t);
        // skip TTL
        p += sizeof(uint32_t);
        // skip 
        if (qtype == qtype_ && qclass == CLASS_IN)
            return p;
        // skip rdlength & rdata
        uint16_t rdlength = ntohs(*(uint16_t *)p);
        p += sizeof(uint16_t) + rdlength;
    }
    return NULL;
}

const char * dns_get_answered_ip(const char * rsp, size_t len)
{
    return _dns_get_answered_ip(rsp, len, QTYPE_A);
}

const char * dns_get_answered_ipv6(const char * rsp, size_t len)
{
    return _dns_get_answered_ip(rsp, len, QTYPE_AAAA);
}

size_t dns_append_edns_opt(char * buf, size_t len, size_t max_len)
{
    struct dns_header_t * header = (struct dns_header_t *)buf;
    const char * opt = dns_get_edns_opt(buf, len);
    // ENDS OPT exists, do nothing to content
    if (opt)
        return len;
    // Too short, do nothing to content 
    if (len < sizeof(*header))
        return len;
    // Append EDNS OPT if there's enough space left
    if (max_len >= len + sizeof(edns_opt)) {
        memcpy(buf + len, edns_opt, sizeof(edns_opt));
        header->arcount = htons(ntohs(header->arcount) + 1);
    }
    // Return new size of content
    return len + sizeof(edns_opt);
}

void dns_init_query(struct dns_header_t * hdr)
{
    if (hdr) {
        memset(hdr, 0, sizeof(*hdr));
        hdr->rd = 1;
    }
}

uint16_t dns_set_id(struct dns_header_t * hdr, uint16_t id)
{
    hdr->id = htons(id);
    return id;
}

uint16_t dns_get_id(struct dns_header_t * hdr)
{
    return ntohs(hdr->id);
}

int dns_get_rcode(const char * rsp, size_t len)
{
    struct dns_header_t * hdr = (struct dns_header_t *)rsp;
    const char * opt = dns_get_edns_opt(rsp, len);

    if (!rsp || len < sizeof(struct dns_header_t))
        return -1;

    if (opt) {
        // For response with ENDS OPT, extended bits of rcode need to be included.
        uint8_t rcode_msb = *(opt 
                                + 1                // NAME
                                + sizeof(uint16_t) // OPT
                                + sizeof(uint16_t) // CLASS
                              );
        return (rcode_msb << RCODE_BITS) | hdr->rcode;
    }
    else {
        return hdr->rcode;
    }
}

const char * dns_get_edns_opt(const char * rsp, size_t len)
{
    struct dns_header_t * header = (struct dns_header_t *)rsp;
    const char * p = (const char *)header;
    uint16_t i;

    if (len <= sizeof(*header) || ntohs(header->arcount) == 0)
        return NULL;
    
    // skip header
    p += sizeof(*header);
    // skip questions
    p = _dns_skip_questions(ntohs(header->qdcount), p);
    // skip answers
    p = _dns_skip_resources(ntohs(header->ancount), p);
    // skip resources
    p = _dns_skip_resources(ntohs(header->nscount), p);

    // Check options
/*
+------------+--------------+------------------------------+
| Field Name | Field Type   | Description                  |
+------------+--------------+------------------------------+
| NAME       | domain name  | MUST be 0 (root domain)      |
| TYPE       | u_int16_t    | OPT (41)                     |
| CLASS      | u_int16_t    | requestor's UDP payload size |
| TTL        | u_int32_t    | extended RCODE and flags     |
| RDLEN      | u_int16_t    | length of all RDATA          |
| RDATA      | octet stream | {attribute,value} pairs      |
+------------+--------------+------------------------------+
*/
    for (i = 0; i < ntohs(header->arcount); i++) {
        if (*p == 0 && *(uint16_t *)(p + 1) == htons(41)) {
            return p;
        }
        // skip QNAME
        p = _dns_skip_qname(p);
        // QTYPE
        p += sizeof(uint16_t);
        // QCLASS
        p += sizeof(uint16_t);
        // TTL
        p += sizeof(uint32_t);
        // skip rdlength & rdata
        uint16_t rdlength = ntohs(*(uint16_t *)p);
        p += sizeof(uint16_t) + rdlength;
    }
    return NULL;
}

bool dns_get_inet_qtype(const char * buf, size_t len, uint16_t * qtype)
{
    struct dns_header_t * hdr = (struct dns_header_t *)buf;
    const char * p = (const char *)hdr;

    if (len <= sizeof(*hdr) || ntohs(hdr->qdcount) == 0)
        return false;
    
    // skip header
    p += sizeof(*hdr);
    // skip QNAME
    p = _dns_skip_qname(p);
    // skip QTYPE
    if (*(uint16_t *)(p += sizeof(uint16_t)) == htons(CLASS_IN)) {
        * qtype = ntohs(*(uint16_t *)p);
        return true;
    }
    return false;
}

/*
Return required size of buffer for final query. If returned size is larger
than buffer size, no change is made to buffer.
*/
static size_t build_query(char * buf, size_t size, uint16_t qtype, const char * dn, int edns)
{
    struct dns_header_t * hdr = (struct dns_header_t *)buf;
    size_t rc = sizeof(struct dns_header_t)
                + sizeof(uint16_t) // QTYPE
                + sizeof(uint16_t) // QCLASS
                + strlen(dn) + 2;
    rc += (edns ? sizeof(edns_opt) : 0);

    char * p = buf;
    if (buf && size >= rc) {
        dns_init_query((struct dns_header_t *)p);
        p += sizeof(struct dns_header_t);
        hdr->qdcount = htons(ntohs(hdr->qdcount) + 1);
        for (;;) {
           char * t = strchr(dn, '.');
           if (!t) {
               *p = (char)(strlen(dn));
               p += 1;
               strcpy(p, dn);
               p += strlen(dn) + 1;
               break;
           }
           else {
               *p = (char)(t - dn);
               p += 1;
               memcpy(p, dn, (t - dn));
               p += t - dn;
               dn = t + 1;
           }
        }
        *(uint16_t *)p = htons(qtype);
        p += sizeof(uint16_t);
        *(uint16_t *)p = htons(CLASS_IN);
        p += sizeof(uint16_t);
        // Add EDNS OPT as additional resource if required
        if (edns) {
            hdr->arcount = htons(ntohs(hdr->arcount) + 1);
            memcpy(p, edns_opt, sizeof(edns_opt));
            p += sizeof(edns_opt);
        }
        assert(p - buf == rc);
    }
    return rc;
}


size_t dns_build_a_query(char * buf, size_t size, const char * dn, int edns)
{
    return build_query(buf, size, QTYPE_A, dn, edns);
}

size_t dns_build_ptr_query(char * buf, size_t size, const char * dn, int edns)
{
    return build_query(buf, size, QTYPE_PTR, dn, edns);
}

int dns_validate_request(const char * req, size_t len)
{
    struct dns_header_t * header = (struct dns_header_t *)req;
    if (len < sizeof(*header))
        return -1;

    if (header->qr == 0 /* query */
       && header->z == 0 /* Z is Zero */
       && ntohs(header->qdcount) /* some questions */
       && !ntohs(header->ancount)/* no answers */
       )
        return 0;
    return -1;
}

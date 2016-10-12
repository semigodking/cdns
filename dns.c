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

uint16_t get_edns_udp_payload_size(const char * rsp, size_t len)
{
    struct dns_header_t * header = (struct dns_header_t *)rsp;
    const char * p = (const char *)header;
    uint16_t i;

    if (len <= sizeof(*header) || ntohs(header->arcount) == 0)
        return 0;
    
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
            return ntohs(*(uint16_t *)(p + 1 + sizeof(uint16_t)));
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
    return 0;
}

const char * get_answered_ip(const char * rsp, size_t len)
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
        uint16_t qtype = ntohs(*(uint16_t *)p);
        p += sizeof(uint16_t);
        uint16_t qclass = ntohs(*(uint16_t *)p); 
        p += sizeof(uint16_t);
        // skip TTL
        p += sizeof(uint32_t);
        // skip 
        if (qtype == QTYPE_A && qclass == CLASS_IN)
            return p;
        // skip rdlength & rdata
        uint16_t rdlength = ntohs(*(uint16_t *)p);
        p += sizeof(uint16_t) + rdlength;
    }
    return NULL;
}

size_t append_edns_opt(char * buf, size_t len, size_t max_len)
{
    struct dns_header_t * header = (struct dns_header_t *)buf;
    if (len < sizeof(*header))
        return len;

    uint16_t size = get_edns_udp_payload_size(buf, len);
    if (size)
        return len;
     
    if (max_len >= len + sizeof(edns_opt)) {
        memcpy(buf + len, edns_opt, sizeof(edns_opt));
        header->arcount = htons(ntohs(header->arcount) + 1);
    }
    return len + sizeof(edns_opt);
}

/*
Return required size of buffer for final query. If returned size is larger
than buffer size, no change is made to buffer.
*/
size_t build_dns_query(char * buf, size_t size, const char * dn, int edns)
{
    static char query_hdr[] = {0x10, 0x33,
                  0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                  };
    static char query_parm[] = {0x00, 0x01, 0x00, 0x01};

    size_t rc = sizeof(query_hdr) + sizeof(query_parm) + strlen(dn) + 2;
    rc += (edns ? sizeof(edns_opt) : 0);

    char * p = buf;
    if (buf && size >= rc) {
        memcpy(p, query_hdr, sizeof(query_hdr));
        p += sizeof(query_hdr);

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

        memcpy(p, query_parm, sizeof(query_parm));
        p += sizeof(query_parm);
        if (edns) {
            memcpy(p, edns_opt, sizeof(edns_opt));
            p += sizeof(edns_opt);
        }
        assert(p - buf == rc);
    }
    return rc;
}



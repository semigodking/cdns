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
#include <string.h>
#include <search.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "event2/event.h"
#include "event2/util.h"
#include "dns.h"
#include "util.h"
#include "cfg.h"
#include "log.h"

#define DEFAULT_TIMEOUT_SECONDS 4
#define DEFAULT_BUFFER_SIZE 4096

#define FLAG_TEST 0x01

struct server_info {
    char *   ip_port;
    bool     force_edns;
    struct sockaddr_in addr;
    // Fields below are for statistics only
    uint16_t edns_udp_size;
    int    avg_rtt; // ms
    int    rtt_count;
    int    rtt_next_pos;
    int    rtt[10]; // round trip time
    struct timeval last_rsp_time;
};

typedef struct dns_request_t {
    struct server_info * server;
    short               state;
    uint16_t            flags;
    uint16_t            id; // id from request message
    uint16_t            timeout; /* timeout value for DNS response */
    struct sockaddr_in  client_addr;
    struct event *      resolver;
    struct timeval      req_recv_time; 
    struct timeval      req_fwd_time; 
} dns_request;

struct dns_test_request_t {
    short                state;
    struct timeval       test_start;
    struct server_info * server;
    struct event *       resolver;
};

typedef enum cdns_state_t {
    STATE_NEW,
    STATE_REQUEST_SENT,
    STATE_RECV_1ST_RSP,
    STATE_RESPONSE_SENT,
} cdns_state;

static struct event * listener = NULL;
/***********************************************************************/
struct cdns_cfg{
    char *  local_ip;
    uint16_t local_port;
    uint16_t timeout;
};

struct cdns_cfg g_cdns_cfg = {"0.0.0.0", 53, DEFAULT_TIMEOUT_SECONDS,};
struct server_info * g_svr_cfg = NULL;
unsigned int g_svr_count = 0;

config_item svritems[] = {{.key = "ip_port",
                         .type = cdt_string,
                        },
                        /*
                        {.key = "force_edns",
                         .type = cdt_bool,
                        },
                        */
                        {.key = NULL,}
                       };


config_item * servers_init_cb(unsigned int count)
{
    void * tmp;
    config_item * items;
    unsigned int i;

    if (g_svr_cfg) {
        free(g_svr_cfg);
        g_svr_cfg = NULL;
        g_svr_count = 0;
    }
    g_svr_cfg = calloc(count, sizeof(* g_svr_cfg));
    g_svr_count = count;

    tmp = calloc(count, sizeof(svritems));
    items = (config_item *)tmp;
    if (tmp){
        for (i = 0; i < count; i++) {
            memcpy(tmp, &svritems[0], sizeof(svritems));
            // Do additional initialization for each item
            config_item * v = cfg_find_item("ip_port", tmp);
            if (v)
                v->value = &g_svr_cfg[i].ip_port;
            v = cfg_find_item("force_edns", tmp);
            if (v) {
                v->value = &g_svr_cfg[i].force_edns;
            }
            tmp += sizeof(svritems);
        }
    }
    return items;
}

void servers_free_cb(config_item * items, unsigned int count)
{
    log_error(LOG_DEBUG, "Free memory for %u servers @ %p", count, items);
    free(items);
    if (g_svr_cfg) {
        free(g_svr_cfg);
        g_svr_cfg = NULL;
        g_svr_count = 0;
    }
}

config_item cdns_cfg_items[] = {{.key = "listen_ip",
                         .type = cdt_string,
                         .value = &g_cdns_cfg.local_ip,
                        },
                        {.key = "listen_port",
                         .type = cdt_uint16,
                         .value = &g_cdns_cfg.local_port,
                        },
                        {.key = "timeout",
                         .type = cdt_uint16,
                         .value = &g_cdns_cfg.timeout,
                        },
                        {.key = "servers",
                         .type = cdt_object,
                         .list = true,
                         .subitems_init_cb = servers_init_cb,
                         .subitems_free_cb = servers_free_cb,
                         .subitems = &cdns_cfg_items[0],
                        },
                        {.key = NULL,}
                       };

bool cdns_validate_cfg()
{
    bool rc = true;
    unsigned int i;
    struct in6_addr addr;
    int len;

    if (evutil_inet_pton(AF_INET, g_cdns_cfg.local_ip, &addr) != 1) {
        log_error(LOG_ERR, "Invalid IP specified for listening address");
        rc = false;
    }
    if (g_cdns_cfg.local_port == 0)
        g_cdns_cfg.local_port = DNS_DEFAULT_PORT;
    if (g_cdns_cfg.timeout == 0)
        g_cdns_cfg.timeout = DEFAULT_TIMEOUT_SECONDS;

    // Validate servers
    if (g_svr_count == 0) {
        log_error(LOG_ERR, "No upstream DNS server specified");
        rc = false;
    }
    for (i = 0; i < g_svr_count; i++) {
        if (g_svr_cfg[i].ip_port) {
            len = sizeof(g_svr_cfg[i].addr);
            if (evutil_parse_sockaddr_port(g_svr_cfg[i].ip_port, (struct sockaddr *)&g_svr_cfg[i].addr, &len)) {
                log_error(LOG_ERR, "Invalid IP:port pair for upstream DNS server: %s", g_svr_cfg[i].ip_port);
                rc = false;
            }
            if (g_svr_cfg[i].addr.sin_port == 0)
                g_svr_cfg[i].addr.sin_port = htons(DNS_DEFAULT_PORT);
        }
        else {
            log_error(LOG_ERR, "IP:port pair is required");
            rc = false;   
        }
    }
    return rc;
}

/***********************************************************************/
struct ipv4_key {
    struct in_addr sin_addr;
} PACKED;

static void* ipv4_blacklist_root = NULL; 

static int ipv4_key_cmp(const void *a, const void *b)
{
     if (a == b)
         return 0;
     else if (a< b)
         return -1;
     else
         return 1; 
}

static void blacklist_add_v4(struct ipv4_key * key)
{
    uint32_t addr = key->sin_addr.s_addr;
    tsearch((void *)addr, &ipv4_blacklist_root, ipv4_key_cmp); 
}

static void * blacklist_find_v4(struct ipv4_key * key)
{
    uint32_t addr = key->sin_addr.s_addr;
    return tfind((void *)addr, &ipv4_blacklist_root, ipv4_key_cmp);
}

/*
static void _blacklist_freenode(void *nodep)
{
}

static void blacklist_reset_v4()
{
    if (ipv4_blacklist_root) {
        tdestroy(ipv4_blacklist_root, _blacklist_freenode);
        ipv4_blacklist_root = NULL;
    }
}
*/

static void add_to_blacklist(const char * rsp, size_t len)
{
    const char * p = get_answered_ip(rsp, len);
    if (p) {
        uint16_t rdlength = ntohs(*(const uint16_t *)p);
        p += sizeof(uint16_t);
        blacklist_add_v4((struct ipv4_key *)p);
        log_error(LOG_DEBUG, "Add to blacklist: %x %u.%u.%u.%u", rdlength, p[0], p[1], p[2], p[3]);
    }
}

/***********************************************************************
 * Logic
 */
static void update_server_rtt(struct server_info * svr, int rtt_ms)
{
    svr->rtt[svr->rtt_next_pos] = rtt_ms;
    svr->rtt_next_pos += 1;
    if (svr->rtt_next_pos >= SIZEOF_ARRAY(svr->rtt))
        svr->rtt_next_pos = 0;

    if (svr->rtt_count < SIZEOF_ARRAY(svr->rtt))
        svr->rtt_count += 1;

    // Calculate average rtt
    long sum = 0;
    for (int i = 0; i < svr->rtt_count; i++)
        sum += svr->rtt[i];
    svr->avg_rtt = sum / svr->rtt_count;
}

static int verify_request(const char * req, size_t len)
{
    struct dns_header_t * header = (struct dns_header_t *)req;
    if (len < sizeof(*header))
        return -1;

    if ((header->qr_opcode_aa_tc_rd & DNS_QR) == 0 /* query */
       && (header->ra_z_rcode & DNS_Z) == 0 /* Z is Zero */
       && ntohs(header->qdcount) /* some questions */
       && !ntohs(header->ancount)/* no answers */
       )
        return 0;
    return -1;
}

/*
 * returns: -1    - invalid response, negative
 *           0    - valid response, neutron
 *           1    - confirmed, positive
 */
static int verify_response(dns_request * req, const char * rsp, size_t len)
{
    struct dns_header_t * header = (struct dns_header_t *)rsp;
    // message too short
    if (len <= sizeof(*header))
        return -1;

    // If server supports EDNS, response with ENDS OPT included is good.
    // Otherwise, it is bad!
    if (req->server->edns_udp_size) {
        if (get_edns_udp_payload_size(rsp, len)) {
            log_error(LOG_DEBUG, "Good response (+edns)");
            return 1;
        }
        else {
            log_error(LOG_DEBUG, "Bad response");
            add_to_blacklist(rsp, len);
            return -1;
        }
    }
    // Good Responses:
    //   1. with more than 1 answers
    //   2. with addition record(s)
    //   3. NXDomain
    if (ntohs(header->ancount) > 1
       || ntohs(header->arcount) > 0
       || (header->ra_z_rcode & DNS_RC_MASK) == DNS_RC_NXDOMAIN
       ) {
        return 1;
    }
    // Bad Responses:
    //   1. IP returned in blacklist
    const char * p = get_answered_ip(rsp, len);
    if (p) {
        uint16_t rdlength = ntohs(*(const uint16_t *)p);
        p += sizeof(uint16_t);
        if (blacklist_find_v4((struct ipv4_key *)p)){
            log_error(LOG_DEBUG, "Found in blacklist: %x %u.%u.%u.%u", rdlength, p[0], p[1], p[2], p[3]);
            return -1;
        }
    }

    return 0;
}

static void cdns_drop_request(dns_request * req)
{
    int fd;
    log_error(LOG_DEBUG, "dropping request @ state: %d", req->state);
    if (req->resolver)
    {
        fd = event_get_fd(req->resolver);
        event_free(req->resolver);
        close(fd);
    }
    free(req);
}

static void cdns_readcb(int fd, short what, void *_arg)
{
    dns_request * req = _arg;
    struct server_info * svr = req->server;
    struct timeval tv, rtt;
    char   buf[DEFAULT_BUFFER_SIZE];
    size_t pktlen;
    int    rc;

    if (what & EV_TIMEOUT) {
        if (req->state != STATE_RESPONSE_SENT) {
            update_server_rtt(svr, req->timeout * 1000);
        }
        goto finish;
    }

    pktlen = recvfrom(fd, &buf[0], sizeof(buf), 0, NULL, NULL);
    if (pktlen == -1)
        goto finish;

    // learn
    if (req->state == STATE_RESPONSE_SENT) {
        // TODO: Unreachable
        if (pktlen >= sizeof(struct dns_header_t))
            add_to_blacklist(&buf[0], pktlen);
        goto finish;
    }
    // Calculate round trip time
    gettimeofday(&tv, 0);
    timersub(&tv, &req->req_fwd_time, &rtt);
    int rtt_ms = rtt.tv_sec * 1000 + rtt.tv_usec/1000;
    
    rc = verify_response(req, &buf[0], pktlen);
    log_error(LOG_DEBUG, "pktlen: %u rtt_ms: %d avg rtt: %d verify_rc: %d",
                         pktlen, rtt_ms, svr->avg_rtt, rc);
    if (rc < 0)
        goto continue_waiting;
    if (rc > 0)
        goto accept;

    // TODO: can not determined?
    if (req->state == STATE_REQUEST_SENT) {
        req->state = STATE_RECV_1ST_RSP;
    }

accept:
    {
        int sender = event_get_fd(listener);
        ssize_t outgoing = sendto(sender, buf, pktlen, 0,
                                  (const struct sockaddr *)&req->client_addr,
                                  sizeof(req->client_addr));
        if (outgoing == -1) {
            log_errno(LOG_DEBUG, "sendto: Can't forward packet");
        }
        else if (outgoing != pktlen) {
            log_error(LOG_DEBUG, "sendto: I was sending %zd bytes, but only %zd were sent.", pktlen, outgoing);
        }
        else {
            update_server_rtt(svr, rtt_ms);
        }
        req->state = STATE_RESPONSE_SENT;
    }
finish:
    cdns_drop_request(req);
    return;

continue_waiting:
    timersub(&tv, &req->req_recv_time, &rtt);
    tv.tv_sec = req->timeout;
    tv.tv_usec = 0;
    timersub(&tv, &rtt, &rtt);
    // update with time left for timeout
    int error = event_add(req->resolver, &rtt);
    if (error) {
        log_errno(LOG_ERR, "event_add");
        cdns_drop_request(req);
    }
    return;

}

#define MAX_SERVERS  16
static struct server_info *
_choose_server(struct server_info ** pservers, int count)
{
    struct server_info * valid_servers[MAX_SERVERS];
    struct server_info * servers[MAX_SERVERS];
    int i, n;
    // no server available
    if (count < 1)
        return NULL;
    // get a list of servers with valid address
    n = 0;
    for (i = 0; i < count; i++) {
        if (pservers[i]->addr.sin_addr.s_addr != htonl(INADDR_ANY)
           && pservers[i]->addr.sin_port != 0) {
            valid_servers[n] = pservers[i];
            n += 1;
            // hardcoded limitation of 16 servers
            if (n >= MAX_SERVERS)
                break;
        }
    }
    count = n;
    // get a list of servers which support EDNS
    n = 0;
    for (i = 0; i < count; i++) {
        if (valid_servers[i]->edns_udp_size) {
            servers[n] = valid_servers[i];
            n += 1;
        }
    }
    // No server supports EDNS
    if (!n) {
        for (i = 0; i < count; i++) {
            servers[n] = valid_servers[i];
            n += 1;
        }
    }
    // find out the one with min RTT
    struct server_info * svr = NULL;
    for (i = 0; i < n; i++)
        if (servers[i]->avg_rtt > 0) {
            if (!svr || servers[i]->avg_rtt < svr->avg_rtt)
                svr = servers[i];
        }
    // No server with RTT updated, return random one
    if (!svr && n) {
        uint16_t r;
        evutil_secure_rng_get_bytes(&r, sizeof(r));
        svr = servers[r % n];
    }
    return svr;
}

static struct server_info * choose_server()
{
    struct server_info * servers[MAX_SERVERS];
    int i = 0;
    int count = g_svr_count <= MAX_SERVERS ? g_svr_count : MAX_SERVERS;

    for (i = 0; i < count; i++)
        servers[i] = g_svr_cfg + i;
    return _choose_server(servers, count);
}

static int forward_dns_request(struct sockaddr * dest_addr, socklen_t dest_len, const void *data, size_t len)
{
    ssize_t outgoing;
    int rc;
    int fd = -1;

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
        log_errno(LOG_ERR, "socket");
        goto fail;
    }

    rc = evutil_make_socket_nonblocking(fd);
    if (rc) {
        log_errno(LOG_ERR, "evutil_make_socket_nonblocking");
        goto fail;
    }

    outgoing = sendto(fd, data, len, 0, dest_addr, dest_len);
    if (outgoing == -1) {
        log_errno(LOG_DEBUG, "sendto: Can't forward packet");
        goto fail;
    }
    else if (outgoing != len) {
        log_error(LOG_DEBUG, "sendto: I was sending %zd bytes, but only %zd were sent.", len, outgoing);
        goto fail;
    }
    return fd;
fail:
    if (fd >= 0) {
        close(fd);
    }
    return -1;
}

static void cdns_pkt_from_client(int fd, short what, void *_arg)
{
    struct event_base * base = _arg;
    dns_request * req = NULL;
    char  buf[DEFAULT_BUFFER_SIZE];
    struct timeval timeout = {g_cdns_cfg.timeout, 0};
    struct sockaddr_in * destaddr;
    socklen_t addr_len;
    ssize_t pktlen;
    int   relay_fd = -1;

    /* allocate and initialize request structure */
    req = (dns_request *)calloc(sizeof(dns_request), 1);
    if (!req) {
        log_error(LOG_ERR, "Out of memeory.");
        goto fail;
    }
    req->state = STATE_NEW;
    req->timeout = g_cdns_cfg.timeout;
    gettimeofday(&req->req_recv_time, 0);

    // Receive DNS request and do basic verification
    addr_len = sizeof(req->client_addr);
    pktlen = recvfrom(fd, &buf[0], sizeof(buf), 0, (struct sockaddr *)&req->client_addr, &addr_len);
    if (pktlen == -1)
        goto fail;

    if (pktlen <= sizeof(struct dns_header_t) || verify_request(&buf[0], pktlen)) {
        log_error(LOG_INFO, "incomplete or malformed DNS request");
        goto fail;
    }

    memcpy(&req->id, &buf[0], sizeof(uint16_t));

    // Choose a server to forward DNS request
    req->server = choose_server();
    if (!req->server) {
        log_error(LOG_WARNING, "No valid DNS resolver available");
        goto fail;
    }
    destaddr = &req->server->addr;

    // append ENDS OPT
    size_t new_size = append_edns_opt(&buf[0], pktlen, sizeof(buf));
    if (new_size <= sizeof(buf))
        pktlen = new_size;
 
    // 1000 ^_^
    /* Forward DNS request to upstream server */
    relay_fd = forward_dns_request((struct sockaddr *)destaddr, sizeof(*destaddr), &buf[0], pktlen);
    if (relay_fd == -1) {
        log_error(LOG_INFO, "Failed to forward DNS request");
        goto fail;
    }
    gettimeofday(&req->req_fwd_time, 0);
    req->resolver = event_new(base, relay_fd, EV_READ | EV_PERSIST, cdns_readcb, req);
    if (!req->resolver) {
        log_errno(LOG_ERR, "event_new");
        goto fail;
    }
    int error = event_add(req->resolver, &timeout);
    if (error) {
        log_errno(LOG_ERR, "event_add");
        goto fail;
    }

    req->state = STATE_REQUEST_SENT;
    return;

fail:
    if (req) {
        if (req->resolver)
            event_free(req->resolver);
        free(req);
    }
    if (relay_fd >= 0)
        close(relay_fd);
}

/***********************************************************************
 * DNS Resolver Delay Checking
 */
static void test_readcb(int fd, short what, void *_arg)
{
    struct dns_test_request_t * req = _arg;
    struct timeval tv, rtt;
    char  buf[DEFAULT_BUFFER_SIZE];
    size_t pktlen;

    if (what & EV_TIMEOUT)
        goto finish;

    pktlen = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
    if (pktlen == -1)
        goto finish;

    gettimeofday(&tv, 0);
    timersub(&tv, &req->test_start, &rtt);

    if (!req->server->edns_udp_size) {
        req->server->edns_udp_size = get_edns_udp_payload_size(&buf[0], pktlen);
        if (req->server->edns_udp_size)
            log_error(LOG_INFO, "Cool! DNS server %s:%u supports EDNS with UDP payload size: %u",
                    evutil_inet_ntop(req->server->addr.sin_family,
                        &req->server->addr.sin_addr,
                        &buf[0],
                        sizeof(buf)),
                    ntohs(req->server->addr.sin_port),
                    req->server->edns_udp_size);
    }
    if (req->server->edns_udp_size) {
        // update server average rtt        
        req->server->avg_rtt = rtt.tv_sec * 1000 + rtt.tv_usec/1000;
    }
    else {
        // Set timeout and wait for next response.
        tv.tv_sec = g_cdns_cfg.timeout;
        tv.tv_usec = 0;
        timersub(&tv, &rtt, &tv);
        if (event_add(req->resolver, &tv)) {
            log_errno(LOG_ERR, "event_add");
            goto finish;
        }    
        return;
    }
finish:
    if (req->resolver)
        event_free(req->resolver);
    free(req);
    close(fd);
}

static void _test_dns(struct event_base * base, struct server_info * svr, const char * query, size_t len)
{
    struct sockaddr_in * destaddr = &svr->addr;
    struct timeval timeout = {DEFAULT_TIMEOUT_SECONDS, 0};
    int relay_fd = -1;

    struct dns_test_request_t * tr = calloc(1, sizeof(struct dns_test_request_t));
    if (!tr) {
        log_error(LOG_ERR, "Out of memeory.");
        goto fail;
    }
    tr->server = svr;

    relay_fd = forward_dns_request((struct sockaddr *)destaddr, sizeof(*destaddr), query, len);
    if (relay_fd == -1) {
        log_error(LOG_INFO, "Failed to forward DNS request");
        goto fail;
    }
    gettimeofday(&tr->test_start, 0);
    tr->resolver = event_new(base, relay_fd, EV_READ | EV_PERSIST, test_readcb, tr);
    if (!tr->resolver) {
        log_errno(LOG_ERR, "event_new");
        goto fail;
    }
    int error = event_add(tr->resolver, &timeout);
    if (error) {
        log_errno(LOG_ERR, "event_add");
        goto fail;
    }

    tr->state = STATE_REQUEST_SENT;
    return;

fail:
    if (tr) {
        if (tr->resolver)
            event_free(tr->resolver);
        free(tr);
    }
    if (relay_fd >= 0)
        close(relay_fd);
}

static char * dn_to_test[] = {"www.baidu.com",
                              "facebook.com",
                              "nonexist.twitter.com"
                             };
static void test_dns(struct event_base * base, struct server_info * svr)
{
    char buf[DEFAULT_BUFFER_SIZE];
    size_t sz;
    char ** dn;

    FOREACH(dn, dn_to_test) {
        sz = build_dns_query(&buf[0], sizeof(buf), *dn, true);
        if (sz <= sizeof(buf)) {
            // generate random id
            evutil_secure_rng_get_bytes(&buf[0], sizeof(uint16_t));
            _test_dns(base, svr, &buf[0], sz);
        }
    }
}

/***********************************************************************
 * Init / shutdown
 */
void cdns_fini_server();

int cdns_init_server(struct event_base * base)
{
    int error;
    int fd = -1;
    struct sockaddr_in addr;

    if (evutil_inet_pton(AF_INET, g_cdns_cfg.local_ip, &addr.sin_addr) != 1) {
        log_error(LOG_ERR, "evutil_inet_pton");
        goto fail;
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_cdns_cfg.local_port);

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
        log_errno(LOG_ERR, "socket");
        goto fail;
    }

    error = bind(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (error) {
        log_errno(LOG_ERR, "bind");
        goto fail;
    }

    error = evutil_make_socket_nonblocking(fd);
    if (error) {
        log_errno(LOG_ERR, "evutil_make_socket_nonblocking");
        goto fail;
    }

    listener = event_new(base, fd, EV_READ | EV_PERSIST, cdns_pkt_from_client, base);
    if (!listener) {
        log_errno(LOG_ERR, "event_new");
        goto fail;
    }
    error = event_add(listener, NULL);
    if (error)
    {
        log_errno(LOG_ERR, "event_add");
        goto fail;
    }

    log_error(LOG_INFO, "cdns @ %s:%u", g_cdns_cfg.local_ip, g_cdns_cfg.local_port);

    for (int i = 0; i < g_svr_count; i++)
        test_dns(base, g_svr_cfg + i);
    return 0;

fail:
    cdns_fini_server();

    if (fd != -1 && close(fd) != 0)
        log_errno(LOG_WARNING, "close");

    return -1;
}

/* Drops instance completely, freeing its memory and removing from
 * instances list.
 */
void cdns_fini_server()
{
    if (listener) {
        if (event_del(listener) != 0)
            log_errno(LOG_WARNING, "event_del");
        if (close(event_get_fd(listener)) != 0)
            log_errno(LOG_WARNING, "close");
        event_free(listener);
        listener = NULL;
    }
}

void cdns_debug_dump()
{
    char buf[INET6_ADDRSTRLEN];

    log_error(LOG_INFO, "Dumping data for DNS servers:");

    for (int i = 0; i < g_svr_count; i++) 
        log_error(LOG_INFO, "DNS %s:%u:  avg rtt: %ums",
                            evutil_inet_ntop(g_svr_cfg[i].addr.sin_family,
                                             &g_svr_cfg[i].addr.sin_addr,
                                             &buf[0],
                                             sizeof(buf)),
                            ntohs(g_svr_cfg[i].addr.sin_port),
                            g_svr_cfg[i].avg_rtt);

    log_error(LOG_INFO, "End of data dumping.");

}


/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */

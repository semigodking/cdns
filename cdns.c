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
#include "blacklist.h"

#define DEFAULT_TIMEOUT_SECONDS 4
#define DEFAULT_BUFFER_SIZE 4096
#define MAX_SERVERS_FOR_ONE_QUERY  2

// Server flags
#define SF_EDNS_OPT (0x01 << 0) // Server supports EDNS
#define SF_NSCOUNT  (0x01 << 1) // Server returns authority records
#define SF_HIJACKED (0x01 << 14) // Server is hijacked
#define SF_TEST_DONE (0x01 << 15) // Tests have been done against server

struct server_stats {
    unsigned int n_req;
    unsigned int n_rsp;
    unsigned int n_drop;
    int    avg_rtt; // ms
    int    rtt_count;
    int    rtt_next_pos;
    int    rtt[10]; // round trip time
    struct timeval last_rsp_time;
};
struct server_info {
    char *   ip_port;
    bool     force_edns;
    uint16_t hijack_threshold;  // In milli-seconds, default to 0
    struct sockaddr_storage addr;
    uint16_t flags;
    uint16_t edns_udp_size;
    struct server_stats stats;
};

typedef struct dns_request_t {
    struct server_info * server;
    short               state;
    uint16_t            flags;
    uint16_t            id; // id from request message
    uint16_t            timeout; /* timeout value for DNS response */
    struct sockaddr_storage  client_addr;
    struct event *      resolver;
    struct timeval      req_recv_time; 
    struct timeval      req_fwd_time; 
} dns_request;

struct dns_test_request_t {
    short                state;
    struct timeval       test_start;
    struct server_info * server;
    struct event *       resolver;
    uint16_t             id; // id from request message
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

config_item svritems[] = {
    { .key = "ip_port", .type = cdt_string, },
    { .key = "hijack_threshold", .type = cdt_uint16, },
    /* {.key = "force_edns", .type = cdt_bool, }, */
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
            v = cfg_find_item("hijack_threshold", tmp);
            if (v) {
                v->value = &g_svr_cfg[i].hijack_threshold;
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
                        },
                        {.key = NULL,}
                       };

bool cdns_validate_cfg()
{
    bool rc = true;
    unsigned int i;
    struct in6_addr addr;
    int len;

    if (evutil_inet_pton(AF_INET, g_cdns_cfg.local_ip, &addr) != 1
        && evutil_inet_pton(AF_INET6, g_cdns_cfg.local_ip, &addr) != 1) {
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
            struct sockaddr * addr = (struct sockaddr*)&g_svr_cfg[i].addr;
            len = sizeof(g_svr_cfg[i].addr);
            if (evutil_parse_sockaddr_port(g_svr_cfg[i].ip_port, addr, &len)) {
                log_error(LOG_ERR, "Invalid IP:port pair for upstream DNS server: %s", g_svr_cfg[i].ip_port);
                rc = false;
            }
            if (g_svr_cfg[i].addr.ss_family == AF_INET && ((struct sockaddr_in*)addr)->sin_port == 0)
                ((struct sockaddr_in*)addr)->sin_port = htons(DNS_DEFAULT_PORT);
            else if (g_svr_cfg[i].addr.ss_family == AF_INET6 && ((struct sockaddr_in6*)addr)->sin6_port == 0)
                ((struct sockaddr_in6*)addr)->sin6_port = htons(DNS_DEFAULT_PORT);
        }
        else {
            log_error(LOG_ERR, "IP:port pair is required");
            rc = false;   
        }
    }
    return rc;
}

/***********************************************************************/
static void add_to_blacklist(const char * rsp, size_t len)
{
    const char * p = dns_get_answered_ip(rsp, len);
    if (p) {
        uint16_t rdlength = ntohs(*(const uint16_t *)p);
        if (rdlength == sizeof(struct ipv4_key)) {
            p += sizeof(uint16_t);
            blacklist_add_v4((struct ipv4_key *)p);
            log_error(LOG_DEBUG, "Add to blacklist: %x %hhu.%hhu.%hhu.%hhu", rdlength, p[0], p[1], p[2], p[3]);
        }
    }
}

static bool is_ip_in_blacklist(const char * rsp, size_t len)
{
    const char * p = dns_get_answered_ip(rsp, len);
    if (p) {
        uint16_t rdlength = ntohs(*(const uint16_t *)p);
        p += sizeof(uint16_t);
        if (rdlength == sizeof(struct ipv4_key) && blacklist_find_v4((struct ipv4_key *)p)){
            log_error(LOG_DEBUG, "Found in blacklist: %x %hhu.%hhu.%hhu.%hhu", rdlength, p[0], p[1], p[2], p[3]);
            return true;
        }
    }
    return false;
}
/***********************************************************************
 * Logic
 */
static void update_server_rtt(struct server_info * svr, int rtt_ms)
{
    svr->stats.rtt[svr->stats.rtt_next_pos] = rtt_ms;
    svr->stats.rtt_next_pos += 1;
    if (svr->stats.rtt_next_pos >= SIZEOF_ARRAY(svr->stats.rtt))
        svr->stats.rtt_next_pos = 0;

    if (svr->stats.rtt_count < SIZEOF_ARRAY(svr->stats.rtt))
        svr->stats.rtt_count += 1;

    // Calculate average rtt
    long sum = 0;
    for (int i = 0; i < svr->stats.rtt_count; i++)
        sum += svr->stats.rtt[i];
    svr->stats.avg_rtt = sum / svr->stats.rtt_count;
}

/*
 * returns: -1    - invalid response, negative
 *           0    - valid response, neutron
 *           1    - confirmed, positive
 */
static int verify_response(dns_request * req, const char * rsp, size_t len)
{
    int rc = 0;
    struct dns_header_t * header = (struct dns_header_t *)rsp;

    // message is too short or is not for this request
    if (len <= sizeof(*header) || req->id != header->id) {
        log_error(LOG_INFO, "Bad response");
        return -1;
    }
    // TODO: Only responses with A/AAAA resources need to be checked

    // If server supports EDNS, response with ENDS OPT included is good.
    // Otherwise, it is bad!
    if (req->server->flags & SF_EDNS_OPT) {
        if (dns_get_edns_udp_payload_size(rsp, len)) {
            log_error(LOG_DEBUG, "Possible good response (+edns)");
            rc = 1;
        }
        else {
            log_error(LOG_DEBUG, "Bad response");
            add_to_blacklist(rsp, len);
            rc = -1;
        }
    }

    // Good Responses:
    //   1. with more than 1 answers
    //   2. with authority record(s)
    //   3. with addition record(s)
    //   4. Errors returned
    if (rc >= 0 && (ntohs(header->ancount) > 1
                 || ntohs(header->nscount) > 0
                 || ntohs(header->arcount) > 0
                 || header->rcode != DNS_RC_NOERROR
                 ))
        // TODO: consider to return here
        rc = 1;

    // Bad Responses:
    //   1. IP returned in blacklist while no CN name in response
    //   2. No authority records returned while server returns authority records
    // TODO: do more check in case correct IP is in blacklist
    if (rc >= 0 && is_ip_in_blacklist(rsp, len)) {
        const char * pcnname = dns_get_answered_cnname(rsp, len);
        if (!pcnname)
            rc = -1;
    }
    if (rc >= 0 && (req->server->flags & SF_NSCOUNT) && ntohs(header->nscount) == 0) {
        log_error(LOG_DEBUG, "Lack of authority records");
        rc = -1;
    }
    return rc;
}

static void cdns_drop_request(dns_request * req)
{
    int fd;
    log_error(LOG_DEBUG, "dropping request %x @ state: %d", req->id, req->state);

    if (req->server)
        req->server->stats.n_drop += 1;
    if (req->resolver) {
        fd = event_get_fd(req->resolver);
        event_free(req->resolver);
        evutil_closesocket(fd);
    }
    free(req);
}

static void cdns_readcb(int fd, short what, void *_arg)
{
    dns_request * req = _arg;
    struct server_info * svr = req->server;
    struct timeval tv, rtt;
    char   buf[DEFAULT_BUFFER_SIZE];
    char   ip_str[INET_ADDR_PORT_STRLEN];
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

    fmt_sockaddr_port((struct sockaddr *)&req->server->addr, &ip_str[0], sizeof(ip_str));
    // Calculate round trip time
    gettimeofday(&tv, 0);
    timersub(&tv, &req->req_fwd_time, &rtt);
    time_t rtt_ms = rtt.tv_sec * 1000 + rtt.tv_usec/1000;
    
    if (svr->hijack_threshold > 0 && rtt_ms <= svr->hijack_threshold) {
        log_error(LOG_DEBUG, "Response received from %s too fast!", &ip_str[0]);
        rc = -1;
    }
    else {
        rc = verify_response(req, &buf[0], pktlen);
    }
    log_error(LOG_DEBUG, "svr: %s req_id: %x pktlen: %zu rtt_ms: %ld avg rtt: %u verify_rc: %d",
              &ip_str[0], req->id, pktlen, rtt_ms, svr->stats.avg_rtt, rc);
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
            svr->stats.n_rsp += 1;
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
    struct sockaddr_in sa_any = {
        .sin_family = AF_INET,
        .sin_addr = {.s_addr = htonl(INADDR_ANY)},
        .sin_port = 0
    };
    struct sockaddr_in6 sa6_any = {
        .sin6_family = AF_INET6,
        .sin6_addr = in6addr_any,
        .sin6_port = 0
    };
    int i, n;
    // no server available
    if (count < 1)
        return NULL;
    // get a list of servers with valid address
    n = 0;
    for (i = 0; i < count; i++) {
        struct sockaddr * addr = (struct sockaddr *)&pservers[i]->addr;
        if (evutil_sockaddr_cmp(addr, (struct sockaddr *)&sa_any, 1)
            || evutil_sockaddr_cmp(addr, (struct sockaddr *)&sa6_any, 1)) {
            valid_servers[n] = pservers[i];
            n += 1;
            // hardcoded limitation of 16 servers
            if (n >= MAX_SERVERS)
                break;
        }
    }
    count = n;
    // TODO: servers with SF_NSCOUNT flag set have higher priority

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
        if (servers[i]->stats.avg_rtt > 0) {
            if (!svr || servers[i]->stats.avg_rtt < svr->stats.avg_rtt)
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

static struct server_info * choose_server(struct server_info ** excludes, int count)
{
    struct server_info * servers[MAX_SERVERS];
    int i, j, k;
    int svr_count = g_svr_count <= MAX_SERVERS ? g_svr_count : MAX_SERVERS;

    k = 0;
    for (i = 0; i < svr_count; i++) {
        bool found = false;
        for (j = 0; j < count; j++)
            if (excludes[j] == g_svr_cfg + i) {
                found = true;
                break;
            }
        if (!found) {
            // Only put a server as candidate if it has been tested and is not hijacked.
            if ((g_svr_cfg[i].flags & SF_TEST_DONE) && !(g_svr_cfg[i].flags & SF_HIJACKED)) {
                servers[k] = g_svr_cfg + i;
                k += 1;
            }
        }
    }
    return _choose_server(servers, k);
}

static int forward_dns_request(struct sockaddr * dest_addr, socklen_t dest_len, const void *data, size_t len)
{
    ssize_t outgoing;
    int rc;
    int fd = -1;

    fd = socket(dest_addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
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
        evutil_closesocket(fd);
    }
    return -1;
}

static void cdns_pkt_from_client(int fd, short what, void *_arg)
{
    struct event_base * base = _arg;
    dns_request * req = NULL;
    char   buf[DEFAULT_BUFFER_SIZE];
    char   ip_str[INET_ADDR_PORT_STRLEN];
    struct timeval timeout = {g_cdns_cfg.timeout, 0};
    struct sockaddr_storage * dest_addr;
    struct sockaddr_storage client_addr;
    socklen_t addr_len;
    ssize_t pktlen;
    int   relay_fd = -1;
    struct server_info * svr, * svrs[MAX_SERVERS_FOR_ONE_QUERY];

    // Receive DNS request and do basic verification
    addr_len = sizeof(client_addr);
    pktlen = recvfrom(fd, &buf[0], sizeof(buf), 0, (struct sockaddr *)&client_addr, &addr_len);
    if (pktlen == -1)
        return;

    if (pktlen <= sizeof(struct dns_header_t) || dns_validate_request(&buf[0], pktlen)) {
        log_error(LOG_INFO, "incomplete or malformed DNS request");
        return;
    }

    // append ENDS OPT
    size_t new_size = dns_append_edns_opt(&buf[0], pktlen, sizeof(buf));
    if (new_size <= sizeof(buf))
        pktlen = new_size;

    // Choose a server to forward DNS request
    memset(svrs, 0, sizeof(svrs));
    svrs[0] = choose_server(NULL, 0);
    if (!svrs[0]) {
        log_error(LOG_WARNING, "No valid DNS resolver available");
        return;
    }
    // Choose additional servers to forward DNS requests
    for (int i = 1; i < SIZEOF_ARRAY(svrs) && svrs[i-1]; i++)
        svrs[i] = choose_server(&svrs[0], i);
    // Forward DNS requests via each chosen server 
    for (int i = 0; i < SIZEOF_ARRAY(svrs); i++) {
        svr = svrs[i];
        if (!svr)
            break;
        /* allocate and initialize request structure */
        req = (dns_request *)calloc(sizeof(dns_request), 1);
        if (!req) {
            log_error(LOG_ERR, "Out of memeory.");
            goto fail;
        }
        req->state = STATE_NEW;
        req->timeout = g_cdns_cfg.timeout;
        gettimeofday(&req->req_recv_time, 0);
        memcpy(&req->id, &buf[0], sizeof(uint16_t));
        memcpy(&req->client_addr, &client_addr, sizeof(client_addr));
        req->server = svr;
        dest_addr = &req->server->addr;

        fmt_sockaddr_port((struct sockaddr *)dest_addr, &ip_str[0], sizeof(ip_str));
        log_error(LOG_DEBUG, "Forwarding request to %s", &ip_str[0]);
        // 1000 ^_^
        /* Forward DNS request to upstream server */
        relay_fd = forward_dns_request((struct sockaddr *)dest_addr, sizeof(*dest_addr), &buf[0], pktlen);
        if (relay_fd == -1) {
            log_error(LOG_INFO, "Failed to forward DNS request");
            goto fail;
        }
        gettimeofday(&req->req_fwd_time, 0);
        req->server->stats.n_req += 1;
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
        continue;

fail:
        if (req) {
            if (req->resolver)
                event_free(req->resolver);
            free(req);
        }
        if (relay_fd >= 0)
            evutil_closesocket(relay_fd);
    }
}

/***********************************************************************
 * DNS Resolver Delay Checking
 */
static bool is_google_dns(const struct sockaddr *addr)
{
    struct sockaddr_in google_addrs [] = {
        {.sin_family = AF_INET,
         .sin_addr = {.s_addr = inet_addr("8.8.8.8")}},
        {.sin_family = AF_INET,
         .sin_addr = {.s_addr = inet_addr("8.8.4.4")}},
    };
    struct sockaddr_in6 google_addrs6 [] = {
        {.sin6_family = AF_INET6},
        {.sin6_family = AF_INET6},
    };
    evutil_inet_pton(AF_INET6, "2001:4860:4860::8888",
                    &google_addrs6[0].sin6_addr);
    evutil_inet_pton(AF_INET6, "2001:4860:4860::8844",
                    &google_addrs6[1].sin6_addr);

    if (addr->sa_family == AF_INET) {
        struct sockaddr_in * google_addr;
        FOREACH(google_addr, google_addrs) {
            if (!evutil_sockaddr_cmp((struct sockaddr *)google_addr,
                                     addr, 0))
                return true;
        }
    }
    else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 * google_addr;
        FOREACH(google_addr, google_addrs6) {
            if (!evutil_sockaddr_cmp((struct sockaddr *)google_addr,
                                     (struct sockaddr *)addr, 0))
                return true;
        }
    }
    return false;
}

static void test_readcb(int fd, short what, void *_arg)
{
    struct dns_test_request_t * req = _arg;
    struct timeval tv, rtt;
    char   ip_str[INET_ADDR_PORT_STRLEN];
    char   buf[DEFAULT_BUFFER_SIZE];
    size_t pktlen;
    struct dns_header_t * hdr = (struct dns_header_t *)buf;

    if (what & EV_TIMEOUT)
        goto finish;

    pktlen = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
    if (pktlen == -1 || pktlen < sizeof(*hdr) || (hdr->rcode != DNS_RC_NOERROR))
        goto finish;

    if (hdr->id != req->id)
        goto finish;

    fmt_sockaddr_port((struct sockaddr *)&req->server->addr, &ip_str[0], sizeof(ip_str));
    gettimeofday(&tv, 0);
    timersub(&tv, &req->test_start, &rtt);
    time_t rtt_ms = rtt.tv_sec * 1000 + rtt.tv_usec/1000;

    req->server->flags |= SF_TEST_DONE;// Server receives response

    /*
    if (req->server->hijack_threshold > 0 && rtt_ms <= req->server->hijack_threshold) {
        log_error(LOG_DEBUG,
                  "Ignore fast response from %s in %ldms(Threshold: %ums)!",
                  &ip_str[0], rtt_ms, req->server->hijack_threshold);
    }
    */
    if (!(req->server->flags & SF_EDNS_OPT)) {
        req->server->edns_udp_size = dns_get_edns_udp_payload_size(&buf[0], pktlen);

        if (req->server->edns_udp_size && !(req->server->flags & SF_HIJACKED)) {
            if (is_google_dns((const struct sockaddr *)&req->server->addr)
                && req->server->edns_udp_size != 512) {
                req->server->flags |= SF_HIJACKED;
            }
            if (req->server->flags & SF_HIJACKED) {
                log_error(LOG_INFO, "Oops! DNS server %s is hijacked with UDP payload size: %u",
                          &ip_str[0], req->server->edns_udp_size);
            }
        }
        if (req->server->edns_udp_size && !(req->server->flags & SF_HIJACKED)) {
            req->server->flags |= SF_EDNS_OPT;
            log_error(LOG_INFO, "Cool! DNS server %s supports EDNS with UDP payload size: %u",
                      &ip_str[0], req->server->edns_udp_size);
        }
    }
    if (!(req->server->flags & (SF_NSCOUNT | SF_HIJACKED))) {
        if (ntohs(hdr->nscount) > 0) {
            req->server->flags |= SF_NSCOUNT;
            log_error(LOG_INFO, "Cool! DNS server %s returns authority records", &ip_str[0]);
        }
    }
    if (req->server->edns_udp_size) {
        // FIXME: update server average rtt
        req->server->stats.avg_rtt = rtt_ms;
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
    evutil_closesocket(fd);
}

static void _test_dns(struct event_base * base, struct server_info * svr, const char * query, size_t len)
{
    struct sockaddr_storage * destaddr = &svr->addr;
    struct timeval timeout = {DEFAULT_TIMEOUT_SECONDS, 0};
    int relay_fd = -1;

    struct dns_test_request_t * tr = calloc(1, sizeof(struct dns_test_request_t));
    if (!tr) {
        log_error(LOG_ERR, "Out of memeory.");
        goto fail;
    }
    tr->server = svr;
    memcpy(&tr->id, query, sizeof(uint16_t));

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
        evutil_closesocket(relay_fd);
}

static char * dn_to_test[] = {"www.baidu.com",
                              "facebook.com",
                              "nonexist.twitter.com",
                             };
static void test_dns(struct event_base * base, struct server_info * svr)
{
    char buf[DEFAULT_BUFFER_SIZE];
    size_t sz;
    char ** dn;

    FOREACH(dn, dn_to_test) {
        sz = dns_build_a_query(&buf[0], sizeof(buf), *dn, true);
        if (sz <= sizeof(buf)) {
            // generate random id
            evutil_secure_rng_get_bytes(&buf[0], sizeof(uint16_t));
            _test_dns(base, svr, &buf[0], sz);
        }
    }
}

static struct event * tester_event = NULL;

static void tester_timer_cb(int sig, short what, void * arg)
{
    struct event_base * base = arg;
    bool found = false;
    for (int i = 0; i < g_svr_count; i++)
        if (!(g_svr_cfg[i].flags & SF_TEST_DONE)) {
            test_dns(base, g_svr_cfg + i);
            found = true;
        }
    if (!found) {
        // All servers have been tested. Stop timer as no need to do more tests.
        evtimer_del(tester_event);
        event_free(tester_event);
        tester_event = NULL;
    }
}

static void start_tester(struct event_base * base)
{
    struct timeval tv = {30, 0};

    tester_event = event_new(base, -1, EV_TIMEOUT|EV_PERSIST, tester_timer_cb, base);
    if (!tester_event) {
        log_errno(LOG_ERR, "event_new");
        return;
    }
    if (evtimer_add(tester_event, &tv)) {
        log_errno(LOG_ERR, "event_add");
        event_free(tester_event);
        tester_event = NULL;
    }
    else
        // Test all servers immediately
        event_active(tester_event, 0, 0);
}
/***********************************************************************
 * Init / shutdown
 */
void cdns_fini_server();

int cdns_init_server(struct event_base * base)
{
    int error;
    int fd = -1;
    struct sockaddr_storage addr;
    struct sockaddr_in * addr4 = (struct sockaddr_in *)&addr;
    struct sockaddr_in6 * addr6 = (struct sockaddr_in6 *)&addr;

    if (evutil_inet_pton(AF_INET6, g_cdns_cfg.local_ip, &addr6->sin6_addr) == 1) {
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(g_cdns_cfg.local_port);
    }
    else if (evutil_inet_pton(AF_INET, g_cdns_cfg.local_ip, &addr4->sin_addr) == 1) {
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(g_cdns_cfg.local_port);
    }
    else {
        log_errno(LOG_ERR, "evutil_inet_pton");
        goto fail;
    }

    fd = socket(addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
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

    // Start tester to collect information for each server
    start_tester(base);
    return 0;

fail:
    cdns_fini_server();

    if (fd != -1 && evutil_closesocket(fd) != 0)
        log_errno(LOG_WARNING, "evutil_closesocket");

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
        if (evutil_closesocket(event_get_fd(listener)) != 0)
            log_errno(LOG_WARNING, "evutil_closesocket");
        event_free(listener);
        listener = NULL;
    }
}

void cdns_debug_dump()
{
    char buf[INET_ADDR_PORT_STRLEN];

    log_error(LOG_INFO, "Dumping data for DNS servers:");

    for (int i = 0; i < g_svr_count; i++) {
        log_error(LOG_INFO, "DNS %s: rsp/req: %u/%u avg rtt: %ums",
                            fmt_sockaddr_port((struct sockaddr *)&g_svr_cfg[i].addr,
                                              &buf[0], sizeof(buf)),
                            g_svr_cfg[i].stats.n_rsp,
                            g_svr_cfg[i].stats.n_req,
                            g_svr_cfg[i].stats.avg_rtt);
    }
    log_error(LOG_INFO, "End of data dumping.");

}


/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */


#ifndef BLACKLIST_H_THU_OCT_20_10_13_25_2016
#define BLACKLIST_H_THU_OCT_20_10_13_25_2016

#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif

#pragma pack(1)
struct ipv4_key {
    struct in_addr sin_addr;
};
#pragma pack()

void * blacklist_find_v4(struct ipv4_key * key);
void   blacklist_add_v4(struct ipv4_key * key);
#if !(defined __FreeBSD__ || defined _WIN32)
void   blacklist_reset_v4();
#endif


/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
#endif /* BLACKLIST_H_THU_OCT_20_10_13_25_2016 */


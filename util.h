#ifndef UTIL_H_SAT_OCT_08_18_00_45_2016
#define UTIL_H_SAT_OCT_08_18_00_45_2016

#define SIZEOF_ARRAY(arr)        (sizeof(arr) / sizeof(arr[0]))
#define FOREACH(ptr, array)      for (ptr = array; ptr < array + SIZEOF_ARRAY(array); ptr++)
#define FOREACH_REV(ptr, array)  for (ptr = array + SIZEOF_ARRAY(array) - 1; ptr >= array; ptr--)

#if INET6_ADDRSTRLEN < INET_ADDRSTRLEN
#       error Impossible happens: INET6_ADDRSTRLEN < INET_ADDRSTRLEN
#else
#       define INET_ADDR_PORT_STRLEN (1 + INET6_ADDRSTRLEN + 1 + 1 + 5 + 1) // [ + addr + ] + : + port + \0
#endif

const char *fmt_sockaddr_port(const struct sockaddr* sa, char* buffer, size_t buffer_size);
/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
#endif /* UTIL_H_SAT_OCT_08_18_00_45_2016 */

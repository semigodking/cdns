#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "util.h"


const char *fmt_sockaddr_port(const struct sockaddr* sa, char* buffer, size_t buffer_size)
{
    const char *retval = 0;
    size_t len = 0;
    uint16_t port;
    const char placeholder[] = "???:???";
    const struct sockaddr_in * sa4 = (const struct sockaddr_in *)sa;
    const struct sockaddr_in6 * sa6 = (const struct sockaddr_in6 *)sa;

    assert(buffer_size >= INET_ADDR_PORT_STRLEN);

    if (sa->sa_family == AF_INET) {
        retval = inet_ntop(AF_INET, &sa4->sin_addr, buffer, buffer_size);
        port = sa4->sin_port;
    }
    else if (sa->sa_family == AF_INET6) {
        buffer[0] = '[';
        retval = inet_ntop(AF_INET6, &sa6->sin6_addr, buffer+1, buffer_size-1);
        port = sa6->sin6_port;
    }
    if (retval) {
        len = strlen(retval);
        if (sa->sa_family == AF_INET6)
            snprintf(buffer + len + 1, buffer_size - len - 1, "]:%d", ntohs(port));
        else
            snprintf(buffer + len, buffer_size - len, ":%d", ntohs(port));
    }
    else {
        strcpy(buffer, placeholder);
    }
    buffer[buffer_size - 1] = '\x0';
    return buffer;
}


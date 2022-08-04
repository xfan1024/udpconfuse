#ifndef __sockaddr_utils_h__
#define __sockaddr_utils_h__

#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SOCKADDR_STRING_MAX         sizeof("[xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:yyy.yyy.yyy.yyy]:zzzzz")
#define SOCKADDR_NOPORT_STRING_MAX  sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:yyy.yyy.yyy.yyy")

bool str2sockaddr(const char *address, int family, struct sockaddr *sa);
bool sockaddr2str(const struct sockaddr *sa, char buffer[SOCKADDR_STRING_MAX]);
bool sockaddr2str_noport(const struct sockaddr *sa, char buffer[SOCKADDR_NOPORT_STRING_MAX]);
unsigned short sockaddrport(const struct sockaddr *sa);
static inline socklen_t sockaddrlen(const struct sockaddr *sa)
{
    switch (sa->sa_family)
    {
    case AF_INET:
        return sizeof(struct sockaddr_in);
    case AF_INET6:
        return sizeof(struct sockaddr_in6);
    }
    return 0;
}

#endif

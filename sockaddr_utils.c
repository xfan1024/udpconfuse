#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "sockaddr_utils.h"

#define FAMILY_SUPPORT_V4 (family == AF_UNSPEC || family == AF_INET)
#define FAMILY_SUPPORT_V6 (family == AF_UNSPEC || family == AF_INET6)

static bool split_host_port(char *s, char **host, char **port)
{
    char *h, *p, *c = NULL;
    if (s[0] == '[')
    {
        h = s + 1;
        char *h_end = strchr(h, ']');
        if (!h_end)
            return false;
        h_end[0] = 0;
        if (h_end[1])
            c = &h_end[1];
    } else
    {
        h = s;
        c = strchr(s, ':');
    }
    p = NULL;
    if (c && *c)
    {
        if (*c != ':')
            return false;
        *c = 0;
        p = c + 1;
    }
    *host = h;
    *port = p;
    return true;
}

bool str2sockaddr(const char *address, int family, struct sockaddr *sa)
{
    char *host;
    char *port;
    char *address_dup = NULL;
    struct addrinfo *result = NULL;
    bool ret = false;
    struct addrinfo hints = {};

    address_dup = strdup(address);
    if (!split_host_port(address_dup, &host, &port))
        goto out;
    hints.ai_family = family;
    if (getaddrinfo(host, port ? port : "0", &hints, &result))
        goto out;
    for (struct addrinfo *rp = result; rp; rp = rp->ai_next)
    {
        if (rp->ai_family == AF_INET || rp->ai_family == AF_INET6)
        {
            memcpy(sa, rp->ai_addr, rp->ai_addrlen);
            ret = true;
            goto out;
        }
    }
out:
    free(address_dup);
    if (result)
        freeaddrinfo(result);
    return ret;
}

bool sockaddr2str_noport(const struct sockaddr *sa, char buffer[SOCKADDR_NOPORT_STRING_MAX])
{
    if (sa->sa_family == AF_INET)
    {
        struct sockaddr_in *sin = (struct sockaddr_in*)sa;
        return inet_ntop(AF_INET, &sin->sin_addr, buffer, SOCKADDR_NOPORT_STRING_MAX) != NULL;
    }
    else if (sa->sa_family == AF_INET6)
    {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)sa;
        return inet_ntop(AF_INET6, &sin6->sin6_addr, buffer, SOCKADDR_NOPORT_STRING_MAX) != NULL;
    }
    return false;
}

unsigned short sockaddrport(const struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
        return ntohs(((struct sockaddr_in*)sa)->sin_port);
    else if (sa->sa_family == AF_INET6)
        return ntohs(((struct sockaddr_in6*)sa)->sin6_port);
    else
        return 0;
}

bool sockaddr2str(const struct sockaddr *sa, char buffer[SOCKADDR_STRING_MAX])
{
    char *w = buffer;

    if (sa->sa_family == AF_INET)
    {
        sockaddr2str_noport(sa, w);
        w += strlen(w);
    }
    else if (sa->sa_family == AF_INET6)
    {
        *w++ = '[';
        sockaddr2str_noport(sa, w);
        w += strlen(w);
        *w++ = ']';
    }
    else
        return false;
    sprintf(w, ":%u", sockaddrport(sa));
    return true;
}

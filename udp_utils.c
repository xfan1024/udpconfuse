#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "sockaddr_utils.h"
#include "udp_utils.h"

int udp_create_server(const struct sockaddr *local)
{
    int res, fd = socket(local->sa_family, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        perror("socket");
        return fd;
    }
    res = 1;
    res = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &res, sizeof(res));
    if (res < 0)
    {
        perror("setsockopt[SO_REUSEADDR]");
        goto err;
    }
    res = bind(fd, local, sockaddrlen(local));
    if (res < 0)
    {
        perror("bind");
        goto err;
    }
    return fd;
err:
    close(fd);
    return res;
}

int udp_create_client(const struct sockaddr *addr)
{
    int res, fd = socket(addr->sa_family, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        perror("socket");
        return fd;
    }
    res = connect(fd, addr, sockaddrlen(addr));
    if (res < 0)
    {
        close(fd);
        return res;
    }
    return fd;
}

int udp_accept(int acceptor, struct sockaddr *addr)
{
    struct sockaddr_storage local;
    int res;
    socklen_t len;

    len = sizeof(local);
    res = getsockname(acceptor, (struct sockaddr*)&local, &len);
    if (res < 0)
    {
        perror("getsockname");
        return res;
    }
    len = sizeof(struct sockaddr_storage);
    res = recvfrom(acceptor, NULL, 0, MSG_PEEK, addr, &len);
    if (res < 0)
    {
        perror("recvfrom[MSG_PEEK]");
        return res;
    }
    res = connect(acceptor, addr, len);
    if (res < 0)
    {
        perror("connect");
        return res;
    }
    res = udp_create_server((struct sockaddr*)&local);
    if (res < 0)
    {
        fprintf(stderr, "create new acceptor fail\n");
        abort();
    }
    return res;
}


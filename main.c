#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <ev.h>
#include "udp_utils.h"
#include "sockaddr_utils.h"
#include "confuse.h"

#ifndef offsetof
#define offsetof(type, member) ((size_t) &((type *)0)->member)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({                      \
                const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
                (type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#define UDP_PAYLOAD_MAX     1472
#define CONNECTION_TIMEOUT  300.

union sockaddr_u
{
  struct sockaddr         sa;
  struct sockaddr_storage ss;
};

struct config
{
    union sockaddr_u bind_addr;
    union sockaddr_u remote_addr;
    int family;
    uint64_t srand;
};

struct udp_pair;

struct udp_connection
{
    int fd;
    ev_timer timeout_watcher;
    ev_io fd_watcher;
    struct udp_pair *pair;
    union sockaddr_u addr;
};

struct udp_pair
{
    struct udp_connection client;
    struct udp_connection server;
    uint8_t buffer[UDP_PAYLOAD_MAX];
    size_t size;
};

struct udp_acceptor
{
    struct ev_io watcher;
    int fd;
};

struct config config;

static void help(const char *prog, int exit_code)
{
    FILE *o = (exit_code == 0 ? stdout : stderr);
    fprintf(o, "Usage: %s options...\n\n", prog);
    fprintf(o, "Options: \n");
    fprintf(o, "  -h, --help              show this page\n");
    fprintf(o, "  -b, --bind              local address\n");
    fprintf(o, "  -r, --remote            remote address\n");
    fprintf(o, "  --srand                 srand for confuse algorithm\n");
    fprintf(o, "  -4                      use IPv4 only\n");
    fprintf(o, "  -6                      use IPv6 only\n");
    exit(exit_code);
}

#define OPT_SRAND 256

void parse_args(int argc, char *argv[])
{
    static const struct option options[] =
    {
        {"bind",    required_argument,  NULL, 'b'},
        {"remote",  required_argument,  NULL, 'r'},
        {"srand",   required_argument,  NULL, OPT_SRAND},
        {"help",    no_argument,        NULL, 'h'},
        {},
    };

    char *b, *r;
    bool h;

    h = false;
    b = r = NULL;

    config.family = AF_UNSPEC;
    config.srand = DEFAULT_SRAND_VAL;
    bool fail = false;
    while (1)
    {
        int options_index;
        int o = getopt_long(argc, argv, "46b:r:h", options, &options_index);
        if (o < 0)
            break;
        switch (o)
        {
        case 'b':
            b = optarg;
            break;
        case 'r':
            r = optarg;
            break;
        case 'h':
            h = true;
            break;
        case '4':
            config.family = AF_INET;
            break;
        case '6':
            config.family = AF_INET6;
            break;
        case OPT_SRAND:
            errno = 0;
            config.srand = strtoull(optarg, NULL, 0);
            if (errno)
            {
                fprintf(stderr, "wrong srand: %s\n", optarg);
                fail = true;
            }
            break;
        }
    }
    if (h)
    {
        help(argv[0], 0);
        exit(0);
    }
    if (!b)
    {
        fprintf(stderr, "missing bind address\n");
        fail = true;
    }
    if (!r)
    {
        fprintf(stderr, "missing remote address\n");
        fail = true;
    }

    if (fail)
        help(argv[0], 1);

    if (!str2sockaddr(b, config.family, &config.bind_addr.sa) || sockaddrport(&config.bind_addr.sa) == 0)
    {
        fprintf(stderr, "wrong bind address: %s\n", b);
        exit(1);
    }

    if (!str2sockaddr(r, config.family, &config.remote_addr.sa) || sockaddrport(&config.remote_addr.sa) == 0)
    {
        fprintf(stderr, "wrong remote address: %s\n", r);
        exit(1);
    }
}

void udp_pair_delete(struct udp_pair *pair, struct ev_loop *loop);


int udp_connection_store_addr(struct udp_connection *conn)
{
    socklen_t len = sizeof(conn->addr);
    return getpeername(conn->fd, &conn->addr.sa, &len);
}

void udp_connection_allow_recv(struct udp_connection *conn, struct ev_loop *loop)
{
    ev_io_stop(loop, &conn->fd_watcher);
    ev_io_set(&conn->fd_watcher, conn->fd, EV_READ);
    ev_io_start(loop, &conn->fd_watcher);
}

void udp_connection_disallow_recv(struct udp_connection *conn, struct ev_loop *loop)
{
    ev_io_stop(loop, &conn->fd_watcher);
}

void udp_connection_allow_send(struct udp_connection *conn, struct ev_loop *loop)
{
    ev_io_stop(loop, &conn->fd_watcher);
    ev_io_set(&conn->fd_watcher, conn->fd, EV_WRITE);
    ev_io_start(loop, &conn->fd_watcher);
}

void udp_connection_disallow_send(struct udp_connection *conn, struct ev_loop *loop)
{
    ev_io_stop(loop, &conn->fd_watcher);
}

void udp_connection_reset_timer(struct udp_connection *conn, struct ev_loop *loop)
{
    ev_timer_stop(loop, &conn->timeout_watcher);
    ev_timer_set(&conn->timeout_watcher, CONNECTION_TIMEOUT, 0);
    ev_timer_start(loop, &conn->timeout_watcher);
}

void udp_connection_recv_cb(struct ev_loop *loop, ev_io *w)
{
    ssize_t sz;
    struct udp_connection *connection = container_of(w, struct udp_connection, fd_watcher);
    struct udp_pair *pair = connection->pair;
    struct udp_connection *another = (connection == &pair->client) ? &pair->server : &pair->client;
    sz = recv(connection->fd, pair->buffer, UDP_PAYLOAD_MAX, 0);
    if (sz <= 0)
    {
        udp_pair_delete(pair, loop);
        return;
    }
    pair->size = (size_t)sz;
    udp_connection_disallow_recv(&pair->client, loop);
    udp_connection_disallow_recv(&pair->server, loop);
    udp_connection_allow_send(another, loop);
    udp_connection_reset_timer(connection, loop);
}

void udp_connection_send_cb(struct ev_loop *loop, ev_io *w)
{
    ssize_t sz;
    struct udp_connection *connection = container_of(w, struct udp_connection, fd_watcher);
    struct udp_pair *pair = connection->pair;
    confuse_data(pair->buffer, pair->size, config.srand);
    sz = send(connection->fd, pair->buffer, pair->size, 0);
    if (sz <= 0)
    {
        udp_pair_delete(pair, loop);
        return;
    }
    udp_connection_disallow_send(connection, loop);
    udp_connection_allow_recv(&pair->client, loop);
    udp_connection_allow_recv(&pair->server, loop);
}

void udp_connection_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
    (void)revents;
    struct udp_connection *connection = container_of(w, struct udp_connection, timeout_watcher);
    struct udp_pair *pair = connection->pair;
    udp_pair_delete(pair, loop);
}

void udp_connection_cb(struct ev_loop *loop, ev_io *w, int revents)
{
    struct udp_connection *connection;
    struct udp_pair *pair;
    if ((revents & EV_READ) && (revents & EV_WRITE))
    {
        fprintf(stderr, "BUG: EV_READ,EV_WRITE both set\n");
        goto err;
    }
    if (revents & EV_READ)
    {
        udp_connection_recv_cb(loop, w);
        return;
    }
    if (revents & EV_WRITE)
    {
        udp_connection_send_cb(loop, w);
        return;
    }
    fprintf(stderr, "BUG: EV_READ,EV_WRITE both not set\n");
err:
    connection = container_of(w, struct udp_connection, fd_watcher);
    pair = connection->pair;
    udp_pair_delete(pair, loop);
}


void udp_pair_create(struct ev_loop *loop, int client_fd)
{
    struct udp_pair *pair = (struct udp_pair*)calloc(1, sizeof(struct udp_pair));
    struct udp_connection *client = &pair->client;
    struct udp_connection *server = &pair->server;
    client->pair = pair;
    server->pair = pair;
    client->fd = client_fd;
    server->fd = -1;
    if (udp_connection_store_addr(client) < 0)
        goto err;
    server->fd = udp_create_client(&config.remote_addr.sa);
    if (udp_connection_store_addr(server) < 0)
        goto err;
    ev_timer_init(&client->timeout_watcher, udp_connection_timeout_cb, CONNECTION_TIMEOUT, 0);
    ev_timer_init(&server->timeout_watcher, udp_connection_timeout_cb, CONNECTION_TIMEOUT, 0);
    ev_init(&client->fd_watcher, udp_connection_cb);
    ev_init(&server->fd_watcher, udp_connection_cb);
    udp_connection_allow_recv(client, loop);
    udp_connection_allow_recv(server, loop);
    return;
    
err:
    if (client->fd >= 0)
        close(client->fd);
    if (server->fd >= 0)
        close(server->fd);
    free(pair);
}

void udp_pair_delete(struct udp_pair *pair, struct ev_loop *loop)
{
    ev_io_stop(loop, &pair->client.fd_watcher);
    ev_io_stop(loop, &pair->server.fd_watcher);
    ev_timer_stop(loop, &pair->client.timeout_watcher);
    ev_timer_stop(loop, &pair->server.timeout_watcher);
    close(pair->client.fd);
    close(pair->server.fd);
    free(pair);
}

void acceptor_cb(struct ev_loop *loop, ev_io *w, int revents)
{
    (void)revents;
    struct sockaddr_storage remote_addr;
    int fd = udp_accept(w->fd, (struct sockaddr*)&remote_addr);
    int client = w->fd;
    // restart watcher for new acceptor
    ev_io_stop(loop, w);
    ev_io_set(w, fd, EV_READ);
    ev_io_start(loop, w);

    udp_pair_create(loop, client);
}

int start_server()
{
    struct ev_loop *loop = ev_default_loop(0);
    struct ev_io watcher;
    int tmp;

    tmp = udp_create_server(&config.bind_addr.sa);
    if (tmp < 0)
        return tmp;
    ev_init(&watcher, acceptor_cb);
    ev_io_set(&watcher, tmp, EV_READ);
    ev_io_start(loop, &watcher);
    ev_run(loop, 0);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
        help(argv[0], 0);
    parse_args(argc, argv);
    return start_server();
}

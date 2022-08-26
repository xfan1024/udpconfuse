#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <ev.h>
#include "udp_utils.h"
#include "sockaddr_utils.h"
#include "confuse.h"
#include "log.h"

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
    char *bind_str;
    char *remote_str;
    int family;
    int log_level;
    uint64_t srand;
    union sockaddr_u bind_addr;
    union sockaddr_u remote_addr;
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
    fprintf(o, "  -h, --help                        show this page\n");
    fprintf(o, "  -b <addr>, --bind <addr>          local address\n");
    fprintf(o, "  -r <addr>, --remote <addr>        remote address\n");
    fprintf(o, "  --srand <value>                   srand for confuse algorithm\n");
    fprintf(o, "  --log-level debug|info|warn|err   set log level\n");
    fprintf(o, "  -4                                use IPv4 only\n");
    fprintf(o, "  -6                                use IPv6 only\n");
    exit(exit_code);
}

#define OPT_SRAND       256
#define OPT_LOG_LEVEL   257

static int log_level_from_string(const char* name)
{
#define startswith(string, pattern) memcmp((pattern), (string), strlen((pattern)))
    if (startswith(name, "debug") == 0)
        return LOG_DEBUG;
    if (startswith(name, "info") == 0)
        return LOG_INFO;
    if (startswith(name, "warn") == 0)
        return LOG_WARNING;
    if (startswith(name, "err") == 0)
        return LOG_ERR;
#undef startswith
    return -1;
}

void parse_args(int argc, char *argv[])
{
    static const struct option options[] =
    {
        {"bind",        required_argument,  NULL, 'b'},
        {"remote",      required_argument,  NULL, 'r'},
        {"srand",       required_argument,  NULL, OPT_SRAND},
        {"log-level",   required_argument,  NULL, OPT_LOG_LEVEL},
        {"help",        no_argument,        NULL, 'h'},
        {},
    };

    int res;
    bool h;

    h = false;

    config.family = AF_UNSPEC;
    config.srand = DEFAULT_SRAND_VAL;
    config.log_level = LOG_WARNING;
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
            config.bind_str = optarg;
            break;
        case 'r':
            config.remote_str = optarg;
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
            config.srand = strtoull(optarg, NULL, 10);
            if (errno)
            {
                fprintf(stderr, "wrong srand: %s\n", optarg);
                fail = true;
            }
            break;
        case OPT_LOG_LEVEL:
            res = log_level_from_string(optarg);
            if (res < 0)
            {
                fprintf(stderr, "wrong log level: %s\n", optarg);
                fail = true;
                break;
            }
            config.log_level = res;
            break;
        default:
            fail = true;
        }
    }
    if (h)
    {
        help(argv[0], 0);
        exit(0);
    }
    if (!config.bind_str)
    {
        fprintf(stderr, "missing bind address\n");
        fail = true;
    }
    if (!config.remote_str)
    {
        fprintf(stderr, "missing remote address\n");
        fail = true;
    }

    if (fail)
        help(argv[0], 1);
}

int setnonblock(int fd)
{
    int res;
    res = fcntl(fd, F_GETFL);
    if (res < 0)
    {
        log_err("fcntl[F_GETFL] on %d fail: %s\n", fd, strerror(errno));
        return res;
    }
    res = fcntl(fd, F_SETFL, res | O_NONBLOCK);
    if (res < 0)
    {
        log_err("fcntl[F_SETFL] on %d fail: %s\n", fd, strerror(errno));
        return res;
    }
    return 0;
}

void udp_pair_delete(struct udp_pair *pair, struct ev_loop *loop);

bool udp_connection_is_client_side(struct udp_connection *conn)
{
    return conn == &conn->pair->client;
}

bool udp_connection_is_server_side(struct udp_connection *conn)
{
    return conn == &conn->pair->server;
}

const char* udp_connection_side_string(struct udp_connection *conn)
{
    return udp_connection_is_client_side(conn) ? "client-side" : "server-side";
}

struct udp_connection* udp_connection_get_another(struct udp_connection *conn)
{
    struct udp_pair *pair = conn->pair;
    return (conn == &pair->client) ? &pair->server : &pair->client;
}

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

// reuturn value:
//   0 means success
//   1 means need to wait kernel buffer avaiable
//   -1 means failed and pair was closed
int udp_connection_do_send(struct udp_connection *conn, bool allow_eagain, struct ev_loop *loop)
{
    struct udp_pair *pair = conn->pair;
    ssize_t sz = send(conn->fd, pair->buffer, pair->size, 0);
    if (sz <= 0)
    {
        if (allow_eagain && errno == EAGAIN)
            return 1;
        if (log_warn_check())
        {
            char straddr[SOCKADDR_STRING_MAX];
            sockaddr2str(&conn->addr.sa, straddr);
            log_warn("send to %s(fd=%d) return %d\n", straddr, conn->fd, (int)sz);
        }
        udp_pair_delete(pair, loop);
        return -1;
    }
    if (log_debug_check())
    {
        char straddr[SOCKADDR_STRING_MAX];
        sockaddr2str(&conn->addr.sa, straddr);
        log_debug("send to %s(fd=%d) return %d\n", straddr, conn->fd, (int)sz);
    }
    return 0;
}

void udp_connection_recv_cb(struct ev_loop *loop, ev_io *w)
{
    ssize_t sz;
    struct udp_connection *connection = container_of(w, struct udp_connection, fd_watcher);
    struct udp_pair *pair = connection->pair;
    struct udp_connection *another = udp_connection_get_another(connection);

    sz = recv(connection->fd, pair->buffer, UDP_PAYLOAD_MAX, 0);
    if (sz <= 0)
    {
        if (log_warn_check())
        {
            char straddr[SOCKADDR_STRING_MAX];
            sockaddr2str(&connection->addr.sa, straddr);
            log_warn("recv from %s(fd=%d) return %d\n", straddr, connection->fd, (int)sz);
        }
        udp_pair_delete(pair, loop);
        return;
    }
    if (log_debug_check())
    {
        char straddr[SOCKADDR_STRING_MAX];
        sockaddr2str(&connection->addr.sa, straddr);
        log_debug("recv from %s(fd=%d) return %d\n", straddr, connection->fd, (int)sz);
    }
    pair->size = (size_t)sz;
    udp_connection_reset_timer(connection, loop);
    if (udp_connection_do_send(another, true, loop) == 1)
    {
        udp_connection_disallow_recv(connection, loop);
        udp_connection_allow_send(another, loop);
    }
}

void udp_connection_send_cb(struct ev_loop *loop, ev_io *w)
{
    struct udp_connection *connection = container_of(w, struct udp_connection, fd_watcher);
    struct udp_pair *pair = connection->pair;
    confuse_data(pair->buffer, pair->size, config.srand);
    if (udp_connection_do_send(connection, false, loop))
        return;
    udp_connection_allow_recv(&pair->client, loop);
    udp_connection_allow_recv(&pair->server, loop);
}

void udp_connection_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
    (void)revents;
    struct udp_connection *connection = container_of(w, struct udp_connection, timeout_watcher);
    struct udp_pair *pair = connection->pair;

    if (log_debug_check())
    {
        char straddr[SOCKADDR_STRING_MAX];
        sockaddr2str(&connection->addr.sa, straddr);
        log_debug("%s(%s) timeout\n", udp_connection_side_string(connection), straddr);
    }
    udp_pair_delete(pair, loop);
}

void udp_connection_cb(struct ev_loop *loop, ev_io *w, int revents)
{
    struct udp_connection *connection;
    struct udp_pair *pair;
    if ((revents & EV_READ) && (revents & EV_WRITE))
    {
        log_err("BUG: EV_READ,EV_WRITE both set\n");
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
    log_err("BUG: EV_READ,EV_WRITE both not set\n");
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
    if (server->fd < 0)
        goto err;
    if (udp_connection_store_addr(server) < 0)
        goto err;
    if (setnonblock(client->fd) < 0)
        goto err;
    if (setnonblock(server->fd) < 0)
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
    if (log_info_check())
    {
        char straddr[SOCKADDR_STRING_MAX];
        sockaddr2str(&pair->client.addr.sa, straddr);
        log_info("close connection: %s\n", straddr);
    }
    close(pair->client.fd);
    close(pair->server.fd);
    free(pair);
}

void acceptor_cb(struct ev_loop *loop, ev_io *w, int revents)
{
    (void)revents;
    union sockaddr_u remote_addr;
    int fd = udp_accept(w->fd, &remote_addr.sa);
    int client = w->fd;
    if (log_info_check())
    {
        char straddr[SOCKADDR_STRING_MAX];
        sockaddr2str(&remote_addr.sa, straddr);
        log_info("accept connection: %s\n", straddr);
    }
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
    if (log_info_check())
    {
        char straddr_bind[SOCKADDR_STRING_MAX];
        char straddr_remote[SOCKADDR_STRING_MAX];
        sockaddr2str(&config.bind_addr.sa, straddr_bind);
        sockaddr2str(&config.remote_addr.sa, straddr_remote);
        log_info("server started: bind %s, remote %s\n", straddr_bind, straddr_remote);
    }
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
    log_level(config.log_level);
    if (!str2sockaddr(config.bind_str, config.family, &config.bind_addr.sa)
        || sockaddrport(&config.bind_addr.sa) == 0)
    {
        log_err("wrong bind address: %s\n", config.bind_str);
        exit(1);
    }

    if (!str2sockaddr(config.remote_str, config.family, &config.remote_addr.sa)
        || sockaddrport(&config.remote_addr.sa) == 0)
    {
        log_err("wrong remote address: %s\n", config.remote_str);
        exit(1);
    }
    return start_server();
}

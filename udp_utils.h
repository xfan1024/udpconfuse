
#ifndef __udp_utils_h__
#define __udp_utils_h__

#include <sys/socket.h>

int udp_create_server(const struct sockaddr *addr);
int udp_create_client(const struct sockaddr *addr);

/* return a new acceptor, old acceptor will be connected */
int udp_accept(int acceptor, struct sockaddr *addr);

#endif

#include "dsink_udp.h"
#include "dtls_srtp.h"
#include <arpa/inet.h>
#include <ei.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/select.h>
#include <unistd.h>

// static void setexit(int sig);

// static int fprinthex(FILE *fp, const char *prefix, const void *b, size_t l);

// static int fprintfinger(FILE *fp, const char *prefix, const X509 *cert);

// static int handle_socket_error(void);

typedef union usockaddr {
  struct sockaddr_storage ss;
  struct sockaddr_in6 s6;
  struct sockaddr_in s4;
} uaddr;

// static bool makesockaddr(const char *straddr, in_port_t port, uaddr *addr);

// socklen_t getsocklen(const uaddr *addr);

// static fd_t prepare_udp_socket(const uaddr *addr);

int mainloop(fd_t fd, SSL_CTX *cfg, const struct timeval *timeout,
             const uaddr *peer, int ei_fd, erlang_pid *to,
             const char *node_name,
             void (*forward_packet)(int, erlang_pid *, const char *, uint8_t *,
                                    unsigned int),
             void (*forward_key_ptrs)(int, erlang_pid *, const char *,
                                      struct srtp_key_ptrs *));

int get_sock_fd(const char *local_addr, in_port_t local_port, fd_t *sock_fd);

int get_ssl_ctx(const char *certfile, const char *pkeyfile, SSL_CTX **ssl_ctx);

int init();
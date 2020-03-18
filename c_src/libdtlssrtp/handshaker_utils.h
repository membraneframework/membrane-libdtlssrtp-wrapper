#include "dsink_udp.h"
#pragma once

#include "dtls_srtp.h"
#include <arpa/inet.h>
#include <ei.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

typedef union usockaddr {
  struct sockaddr_storage ss;
  struct sockaddr_in6 s6;
  struct sockaddr_in s4;
} uaddr;

int mainloop(fd_t fd, SSL_CTX *cfg, const struct timeval *timeout,
             const uaddr *peer, void *args,
             void (*forward_packet)(void *args, const uint8_t *, unsigned int),
             void (*forward_key_ptrs)(void *, const uint8_t *, const uint8_t *,
                                      const uint8_t *, const uint8_t *));

int get_sock_fd(const char *local_addr, in_port_t local_port, fd_t *sock_fd);

int get_ssl_ctx(const char *certfile, const char *pkeyfile, SSL_CTX **ssl_ctx);

int init();

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

#include "socket.h"

int udp_socket_open(UdpSocket* udp_socket, int family, int port) 
{
  int ret;
  int reuse = 1;
  struct sockaddr* sa;
  socklen_t sock_len;

  udp_socket->bind_addr.family = family;
  switch (family) {
    case AF_INET6:
      udp_socket->fd = socket(AF_INET6, SOCK_DGRAM, 0);
      udp_socket->bind_addr.sin6.sin6_family = AF_INET6;
      udp_socket->bind_addr.sin6.sin6_port = htons(port);
      udp_socket->bind_addr.sin6.sin6_addr = in6addr_any;
      udp_socket->bind_addr.port = ntohs(udp_socket->bind_addr.sin6.sin6_port);
      sa = (struct sockaddr*)&udp_socket->bind_addr.sin6;
      sock_len = sizeof(struct sockaddr_in6);
      break;
    case AF_INET:
    default:
      udp_socket->fd = socket(AF_INET, SOCK_DGRAM, 0);
      udp_socket->bind_addr.sin.sin_family = AF_INET;
      udp_socket->bind_addr.sin.sin_port = htons(port);
      udp_socket->bind_addr.sin.sin_addr.s_addr = htonl(INADDR_ANY);
      sa = (struct sockaddr*)&udp_socket->bind_addr.sin;
      sock_len = sizeof(struct sockaddr_in);
      break;
  }

  if (udp_socket->fd < 0) {
    printf("Failed to create socket");
    return -1;
  }

  do {
    if ((ret = setsockopt(udp_socket->fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) < 0) {
      printf("reuse failed. ignore");
    }

    if ((ret = bind(udp_socket->fd, sa, sock_len)) < 0) {
      printf("Failed to bind socket: %d", ret);
      break;
    }

    if (getsockname(udp_socket->fd, sa, &sock_len) < 0) {
      printf("Get socket info failed");
      break;
    }
  } while (0);

  if (ret < 0) {
    udp_socket_close(udp_socket);

    return -1;
  }

  switch (udp_socket->bind_addr.family) {
    case AF_INET6:
      udp_socket->bind_addr.port = ntohs(udp_socket->bind_addr.sin6.sin6_port);
      break;
    case AF_INET:
    default:
      udp_socket->bind_addr.port = ntohs(udp_socket->bind_addr.sin.sin_port);
      break;
  }

  return 0;
}

void udp_socket_close(UdpSocket* udp_socket) {
  if (udp_socket->fd > 0) {
    close(udp_socket->fd);
  }
}

int udp_socket_sendto(UdpSocket* udp_socket, Address* addr, const uint8_t* buf, int len) {
  struct sockaddr* sa;
  socklen_t sock_len;
  int ret = -1;

  if (udp_socket->fd < 0) {
    printf("sendto before socket init");
    return -1;
  }

  switch (addr->family) {
    case AF_INET6:
      addr->sin6.sin6_family = AF_INET6;
      sa = (struct sockaddr*)&addr->sin6;
      sock_len = sizeof(struct sockaddr_in6);
      break;
    case AF_INET:
    default:
      addr->sin.sin_family = AF_INET;
      sa = (struct sockaddr*)&addr->sin;
      sock_len = sizeof(struct sockaddr_in);
      break;
  }

  if ((ret = sendto(udp_socket->fd, buf, len, 0, sa, sock_len)) < 0) {
    printf("Failed to sendto: %s\n", strerror(errno));
    return -1;
  }

  return ret;
}

int udp_socket_recvfrom(UdpSocket* udp_socket, Address* addr, uint8_t* buf, int len) {
  struct sockaddr_in6 sin6;
  struct sockaddr_in sin;
  struct sockaddr* sa;
  socklen_t sock_len;
  int ret;

  if (udp_socket->fd < 0) {
    printf("recvfrom before socket init");
    return -1;
  }

  switch (udp_socket->bind_addr.family) {
    case AF_INET6:
      sin6.sin6_family = AF_INET6;
      sa = (struct sockaddr*)&sin6;
      sock_len = sizeof(struct sockaddr_in6);
      break;
    case AF_INET:
    default:
      sin.sin_family = AF_INET;
      sa = (struct sockaddr*)&sin;
      sock_len = sizeof(struct sockaddr_in);
      break;
  }

  if ((ret = recvfrom(udp_socket->fd, buf, len, 0, sa, &sock_len)) < 0) {
    printf("Failed to recvfrom: %s", strerror(errno));
    return -1;
  }

  if (addr) {
    switch (udp_socket->bind_addr.family) {
      case AF_INET6:
        addr->family = AF_INET6;
        addr->port = htons(sin6.sin6_port);
        memcpy(&addr->sin6, &sin6, sizeof(struct sockaddr_in6));
        break;
      case AF_INET:
      default:
        addr->family = AF_INET;
        addr->port = htons(sin.sin_port);
        memcpy(&addr->sin, &sin, sizeof(struct sockaddr_in));
        break;
    }
  }

  return ret;
}



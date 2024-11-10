
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtls.h"

void test_handshake(int argc, char* argv[]) {
#if 1
  dtls_context_t dtls;
  UdpSocket udp_socket;
  Address local_addr;
  Address remote_addr;

  if (argc < 2) {

    printf("Usage: %s client/server\n", argv[0]);
    return;
  }

  local_addr.family = AF_INET;
  local_addr.sin.sin_addr.s_addr = inet_addr("192.168.1.110");

  remote_addr.family = AF_INET;
  remote_addr.sin.sin_addr.s_addr = inet_addr("192.168.1.110");


  if (strstr(argv[1], "client")) {

    local_addr.port = 1234;
    remote_addr.port = 5677; // 5678 for MNDP
    dtls_init(&dtls, DTLS_CLIENT, &udp_socket);

  } else {

    local_addr.port = 5677; // 5678 for MNDP
    remote_addr.port = 1234;
    dtls_init(&dtls, DTLS_SERVER, &udp_socket);
  }

  udp_socket_open(&udp_socket, AF_INET, local_addr.port);

  udp_socket_bind(&udp_socket, &local_addr);

  dtls_handshake(&dtls, &remote_addr);

  char buf[64];

  memset(buf, 0, sizeof(buf));

  if (strstr(argv[1], "client")) {

    snprintf(buf, sizeof(buf), "hello from client");

    printf("client sending: %s\n", buf);

    usleep(100 * 1000);

    dtls_write(&dtls, buf, sizeof(buf));

    dtls_read(&dtls, buf, sizeof(buf));

    printf("client received: %s\n", buf);

  } else {

    dtls_read(&dtls, buf, sizeof(buf));

    printf("server received: %s\n", buf);

    snprintf(buf, sizeof(buf), "hello from server");

    printf("server sending: %s\n", buf);

    usleep(100 * 1000);

    dtls_write(&dtls, buf, sizeof(buf));

  }

  dtls_deinit(&dtls);
#endif
}

void test_reset() {
  dtls_context_t dtls;
  dtls_init(&dtls, DTLS_CLIENT, NULL);
  dtls_deinit(&dtls);
}

int main(int argc, char* argv[]) {
  test_reset();
  test_handshake(argc, argv);

  return 0;
}

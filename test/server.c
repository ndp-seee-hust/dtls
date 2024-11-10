#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtls.h"

int main()
{
    dtls_context_t dtls;
    UdpSocket udp_socket;
    Address local_addr;
    Address remote_addr;

    local_addr.family = AF_INET;
    local_addr.sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    local_addr.port = 8080;

    remote_addr.family = AF_INET;
    remote_addr.sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    remote_addr.port = 6060;

    dtls_init(&dtls, DTLS_SERVER, &udp_socket);

    udp_socket_open(&udp_socket, AF_INET, local_addr.port);

    dtls_handshake(&dtls, &remote_addr);

    dtls_deinit(&dtls);
}
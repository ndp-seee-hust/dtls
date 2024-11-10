// File: server.c
#include <stdio.h>
#include <string.h>
#include "socket.h"
#include "dtls.h"

int main() {

    dtls_context_t dtls_ctx;
    UdpSocket server_socket;
    uint8_t buffer[1024];
    Address client_addr;
    int ret;

    if (udp_socket_open(&server_socket, AF_INET, 8080) == 0) {
        printf("Server is running on port 8080...\n");

        dtls_init(&dtls_ctx, DTLS_SERVER, &server_socket);

        ret = dtls_handshake(&dtls_ctx, &client_addr);
        if (ret != 0) {
            fprintf(stderr, "Handshake failed.\n");
            dtls_deinit(&dtls_ctx);
            udp_socket_close(&server_socket);
            return -1;
        }

        udp_socket_close(&server_socket);
    } else {
        printf("Failed to open server socket\n");
    }

    return 0;
}

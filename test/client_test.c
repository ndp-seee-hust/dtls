// File: client.c
#include <stdio.h>
#include <string.h>
#include "socket.h"
#include "dtls.h"

int main() {

    dtls_context_t dtls_ctx;
    UdpSocket client_socket;
    Address server_addr;
    uint8_t buffer[1024];
    int ret;

    client_socket.bind_addr.family = AF_INET;
    client_socket.bind_addr.sin.sin_family = AF_INET;
    client_socket.bind_addr.sin.sin_port = htons(9090);
    inet_pton(AF_INET, "127.0.0.1", &client_socket.bind_addr.sin.sin_addr);
    

    if (udp_socket_open(&client_socket, AF_INET, 9090) == 0) {
        printf("Client socket created\n");

        server_addr.family = AF_INET;
        server_addr.sin.sin_family = AF_INET;
        server_addr.sin.sin_port = htons(8080);
        inet_pton(AF_INET, "127.0.0.1", &server_addr.sin.sin_addr);

        dtls_init(&dtls_ctx, DTLS_CLIENT, &client_socket);

        ret = dtls_handshake(&dtls_ctx, &server_addr);
        if (ret != 0) {
            fprintf(stderr, "Handshake failed.\n");
            dtls_deinit(&dtls_ctx);
            udp_socket_close(&client_socket);
            return -1;
        }

        udp_socket_close(&client_socket);
    } else {
        printf("Failed to open client socket\n");
    }

    return 0;
}

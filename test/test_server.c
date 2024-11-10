#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "socket.h"
#include "dtls.h"

#define SERVER_PORT 12345
#define BUFFER_SIZE 1024

int main() {
    UdpSocket server_socket;
    dtls_context_t dtls_ctx;
    Address client_addr;
    unsigned char buffer[BUFFER_SIZE];
    int ret;

    // Open UDP socket
    if (udp_socket_open(&server_socket, AF_INET, SERVER_PORT) != 0) {
        fprintf(stderr, "Failed to open server socket.\n");
        return -1;
    }

    printf("Server listening on port %d...\n", SERVER_PORT);

    // Initialize DTLS context as a server
    dtls_init(&dtls_ctx, DTLS_SERVER, &server_socket);

    // Perform handshake with client
    ret = dtls_handshake(&dtls_ctx, &client_addr);
    if (ret != 0) {
        fprintf(stderr, "Handshake failed.\n");
        dtls_deinit(&dtls_ctx);
        udp_socket_close(&server_socket);
        return -1;
    }

    printf("Handshake successful. Ready to receive data.\n");

    // Receive data from client
    while ((ret = dtls_read(&dtls_ctx, buffer, BUFFER_SIZE)) > 0) {
        printf("Received: %s\n", buffer);
        dtls_write(&dtls_ctx, (unsigned char *)"Message received", 16);
    }

    if (ret < 0) {
        fprintf(stderr, "Failed to read data.\n");
    }

    dtls_deinit(&dtls_ctx);
    udp_socket_close(&server_socket);

    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "socket.h"
#include "dtls.h"

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 12345
#define BUFFER_SIZE 1024

int main() {
    UdpSocket client_socket;
    dtls_context_t dtls_ctx;
    Address server_addr;
    unsigned char buffer[BUFFER_SIZE];
    int ret;

    // Configure server address
    memset(&server_addr, 0, sizeof(Address));
    server_addr.family = AF_INET;
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin.sin_addr);
    server_addr.port = SERVER_PORT;

    // Open UDP socket
    if (udp_socket_open(&client_socket, AF_INET, 0) != 0) {
        fprintf(stderr, "Failed to open client socket.\n");
        return -1;
    }

    // Initialize DTLS context as a client
    dtls_init(&dtls_ctx, DTLS_CLIENT, &client_socket);

    // Perform handshake with server
    ret = dtls_handshake(&dtls_ctx, &server_addr);
    if (ret != 0) {
        fprintf(stderr, "Handshake failed.\n");
        dtls_deinit(&dtls_ctx);
        udp_socket_close(&client_socket);
        return -1;
    }

    printf("Handshake successful. Sending data to server.\n");

    // Send data to server
    dtls_write(&dtls_ctx, (unsigned char *)"Hello, server!", 14);

    // Receive response from server
    ret = dtls_read(&dtls_ctx, buffer, BUFFER_SIZE);
    if (ret > 0) {
        printf("Server response: %s\n", buffer);
    } else {
        fprintf(stderr, "Failed to read response.\n");
    }

    dtls_deinit(&dtls_ctx);
    udp_socket_close(&client_socket);

    return 0;
}

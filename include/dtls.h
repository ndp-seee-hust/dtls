#ifndef DTLS_H_
#define DTLS_H_

#include <stdio.h>
#include <stdlib.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/timing.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"

#include "socket.h"

#define DTLS_FINGERPRINT_LENGTH 160

typedef enum dtls_role{
    DTLS_CLIENT,
    DTLS_SERVER
} dtls_role_t;

typedef enum dtls_state{
    DTLS_STATE_INIT,
    DTLS_STATE_HANDSHAKE,
    DTLS_STATE_CONNECTED
} dtls_state_t;

typedef struct dtls_context{
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ssl_cookie_ctx cookie_ctx;
    mbedtls_x509_crt cert;
    mbedtls_pk_context pkey;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    int (*udp_send)(void *ctx, const unsigned char *buf, size_t len);
    int (*udp_recv)(void *ctx, unsigned char *buf, size_t len);

    Address *remote_addr;

    dtls_role_t role;
    dtls_state_t state;

    char local_fingerprint[DTLS_FINGERPRINT_LENGTH];
    char remote_fingerprint[DTLS_FINGERPRINT_LENGTH];
    char actual_remote_fingerprint[DTLS_FINGERPRINT_LENGTH];

    void *user_data;

} dtls_context_t;

int dtls_init(dtls_context_t *dtls, dtls_role_t role, void* user_data);
void dtls_deinit(dtls_context_t *dtls);
int dtls_handshake(dtls_context_t *dtls, Address* addr);
void dtls_reset_session(dtls_context_t *dtls);
int dtls_write(dtls_context_t *dtls, const unsigned char* buf, size_t len);
int dtls_read(dtls_context_t *dtls, unsigned char* buf, size_t len);
int dtls_probe(uint8_t* buf);
int gen_key_pair(mbedtls_pk_context *pkey, const char *key_type, int key_size);
int write_private_key(mbedtls_pk_context *pkey, const char *format, const char *file_name);
int write_public_key(mbedtls_pk_context *pkey, const char *format, const char *file_name);

#endif 
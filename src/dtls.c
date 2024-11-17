
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "dtls.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ssl.h"
#include "socket.h"
#include "net_sockets.h"


static int dtls_udp_send(void* ctx, const uint8_t* buf, size_t len) {
  dtls_context_t *dtls= (dtls_context_t *)ctx;
  UdpSocket* udp_socket = (UdpSocket*)dtls->user_data;

  int ret = udp_socket_sendto(udp_socket, dtls->remote_addr, buf, len);

  printf("dtls_udp_send (%d)\n", ret);

  return ret;
}

static int dtls_udp_recv(void* ctx, uint8_t* buf, size_t len) {
  dtls_context_t *dtls = (dtls_context_t *)ctx;
  UdpSocket* udp_socket = (UdpSocket*)dtls->user_data;

  int ret;

  while ((ret = udp_socket_recvfrom(udp_socket, &udp_socket->bind_addr, buf, len)) <= 0) {
    sleep(1);
  }

  printf("dtls_srtp_udp_recv (%d)\n", ret);

  return ret;
}

/*
    Calculate SHA-256 fingerprint from peer's certification
    --> Format 1A:2B:3C ...
*/
static void dtls_x509_digest(const mbedtls_x509_crt* crt, char* buf) {
  int i;
  unsigned char digest[32];
  
  mbedtls_sha256_context sha256_ctx;
  mbedtls_sha256_init(&sha256_ctx);
  mbedtls_sha256_starts(&sha256_ctx, 0);
  mbedtls_sha256_update(&sha256_ctx, crt->raw.p, crt->raw.len);
  mbedtls_sha256_finish(&sha256_ctx, (unsigned char*)digest);
  mbedtls_sha256_free(&sha256_ctx);

  for (i = 0; i < 32; i++) {
    snprintf(buf, 4, "%.2X:", digest[i]);
    buf += 3;
  }

  *(--buf) = '\0';
}

/*
    Callback skip verify CA
    use for test
*/
static int dtls_cert_verify(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags) {
  *flags &= ~(MBEDTLS_X509_BADCERT_NOT_TRUSTED | MBEDTLS_X509_BADCERT_CN_MISMATCH | MBEDTLS_X509_BADCERT_BAD_KEY);
  return 0;
}

/*
    create self-sign certification
    generate random number -> generate key (RSA) -> generate certification (PEM format)
    use for test
*/

static int dtls_selfsign_cert(dtls_context_t *dtls) {
  int ret;

  mbedtls_x509write_cert crt;

  unsigned char* cert_buf = NULL;
  const char* serial = "peer";
  const char* pers = "dtls";

  cert_buf = (unsigned char*)malloc(RSA_KEY_LENGTH * 2);
  if (cert_buf == NULL) {
    printf("malloc failed");
    return -1;
  }

  mbedtls_ctr_drbg_seed(&dtls->ctr_drbg, mbedtls_entropy_func, &dtls->entropy, (const unsigned char*)pers, strlen(pers));

  mbedtls_pk_setup(&dtls->pkey, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));

  mbedtls_rsa_gen_key(mbedtls_pk_rsa(dtls->pkey), mbedtls_ctr_drbg_random, &dtls->ctr_drbg, RSA_KEY_LENGTH, 65537);

  mbedtls_x509write_crt_init(&crt);

  mbedtls_x509write_crt_set_subject_key(&crt, &dtls->pkey);

  mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);

  mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);

  mbedtls_x509write_crt_set_subject_key(&crt, &dtls->pkey);

  mbedtls_x509write_crt_set_issuer_key(&crt, &dtls->pkey);

  mbedtls_x509write_crt_set_subject_name(&crt, "CN=dtls");

  mbedtls_x509write_crt_set_issuer_name(&crt, "CN=dtls");

  mbedtls_x509write_crt_set_serial_raw(&crt, (unsigned char*)serial, strlen(serial));

  mbedtls_x509write_crt_set_validity(&crt, "20240101000000", "20300101000000");

  ret = mbedtls_x509write_crt_pem(&crt, cert_buf, 2 * RSA_KEY_LENGTH, mbedtls_ctr_drbg_random, &dtls->ctr_drbg);

  if (ret < 0) {
    printf("mbedtls_x509write_crt_pem failed -0x%.4x", (unsigned int)-ret);
  }

  mbedtls_x509_crt_parse(&dtls->cert, cert_buf, 2 * RSA_KEY_LENGTH);

  mbedtls_x509write_crt_free(&crt);

  free(cert_buf);

  return ret;
}


int dtls_init(dtls_context_t *dtls, dtls_role_t role, void *user_data) {

  dtls->role = role;
  dtls->state = DTLS_STATE_INIT;
  dtls->user_data = user_data;
  dtls->udp_send = dtls_udp_send;
  dtls->udp_recv = dtls_udp_recv;

  mbedtls_ssl_config_init(&dtls->conf);
  mbedtls_ssl_init(&dtls->ssl);

  mbedtls_x509_crt_init(&dtls->cert);
  mbedtls_pk_init(&dtls->pkey);
  mbedtls_entropy_init(&dtls->entropy);
  mbedtls_ctr_drbg_init(&dtls->ctr_drbg);

  dtls_selfsign_cert(dtls);

  mbedtls_ssl_conf_verify(&dtls->conf, dtls_cert_verify, NULL);

  mbedtls_ssl_conf_authmode(&dtls->conf, MBEDTLS_SSL_VERIFY_REQUIRED);

  mbedtls_ssl_conf_ca_chain(&dtls->conf, &dtls->cert, NULL);

  mbedtls_ssl_conf_own_cert(&dtls->conf, &dtls->cert, &dtls->pkey);

  mbedtls_ssl_conf_rng(&dtls->conf, mbedtls_ctr_drbg_random, &dtls->ctr_drbg);

  mbedtls_ssl_conf_read_timeout(&dtls->conf, 1000);

  if (dtls->role == DTLS_SERVER) {
    mbedtls_ssl_config_defaults(&dtls->conf,
                                MBEDTLS_SSL_IS_SERVER,
                                MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);

    mbedtls_ssl_cookie_init(&dtls->cookie_ctx);

    mbedtls_ssl_cookie_setup(&dtls->cookie_ctx, mbedtls_ctr_drbg_random, &dtls->ctr_drbg);

    mbedtls_ssl_conf_dtls_cookies(&dtls->conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, &dtls->cookie_ctx);

  } else {
    mbedtls_ssl_config_defaults(&dtls->conf,
                                MBEDTLS_SSL_IS_CLIENT,
                                MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);
  }


  dtls_x509_digest(&dtls->cert, dtls->local_fingerprint);

   
  printf("Local fingerprint: %s\n", dtls->local_fingerprint);
  fflush(stdout);

  mbedtls_ssl_conf_cert_req_ca_list(&dtls->conf, MBEDTLS_SSL_CERT_REQ_CA_LIST_DISABLED);

  mbedtls_ssl_setup(&dtls->ssl, &dtls->conf);

  return 0;
}

void dtls_deinit(dtls_context_t *dtls) {
  mbedtls_ssl_free(&dtls->ssl);
  mbedtls_ssl_config_free(&dtls->conf);

  mbedtls_x509_crt_free(&dtls->cert);
  mbedtls_pk_free(&dtls->pkey);
  mbedtls_entropy_free(&dtls->entropy);
  mbedtls_ctr_drbg_free(&dtls->ctr_drbg);

  if (dtls->role == DTLS_SERVER) {
    mbedtls_ssl_cookie_free(&dtls->cookie_ctx);
  }
}


static int dtls_do_handshake(dtls_context_t *dtls) {
  int ret;

  static mbedtls_timing_delay_context timer;

  mbedtls_ssl_set_timer_cb(&dtls->ssl, &timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);

  mbedtls_ssl_set_bio(&dtls->ssl, dtls, dtls->udp_send, dtls->udp_recv, NULL);
  
  do {
    ret = mbedtls_ssl_handshake(&dtls->ssl);

  } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  return ret;
}

static int dtls_handshake_server(dtls_context_t *dtls) {
  int ret;

  while (1) {
    unsigned char client_ip[] = "test";

    mbedtls_ssl_session_reset(&dtls->ssl);

    mbedtls_ssl_set_client_transport_id(&dtls->ssl, client_ip, sizeof(client_ip));

    ret = dtls_do_handshake(dtls);

    if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
      printf("DTLS hello verification requested\n");

    } else if (ret != 0) {
      printf("Failed! mbedtls_ssl_handshake returned -0x%.4x\n", (unsigned int)-ret);

      break;

    } else {
      break;
    }
  }

  printf("DTLS server handshake done\n");

  return ret;
}

static int dtls_handshake_client(dtls_context_t *dtls) {
  int ret;

  ret = dtls_do_handshake(dtls);
  if (ret != 0) {
    printf("failed! mbedtls_ssl_handshake returned -0x%.4x\n", (unsigned int)-ret);
    return -1;
  }

  printf("DTLS client handshake done\n");

  return ret;
}

int dtls_handshake(dtls_context_t *dtls, Address* addr) {
  int ret;
  dtls->remote_addr = addr;

  if (dtls->role == DTLS_SERVER) {
    ret = dtls_handshake_server(dtls);
  } else {
    ret = dtls_handshake_client(dtls);
  }

  const mbedtls_x509_crt* remote_crt;
  if ((remote_crt = mbedtls_ssl_get_peer_cert(&dtls->ssl)) != NULL) {
    dtls_x509_digest(remote_crt, dtls->actual_remote_fingerprint);

    if (strncmp(dtls->remote_fingerprint, dtls->actual_remote_fingerprint, DTLS_FINGERPRINT_LENGTH) != 0) {
      printf("Actual and Expected Fingerprint mismatch: %s %s\n",
           dtls->remote_fingerprint,
           dtls->actual_remote_fingerprint);
      return -1;
    }

  } else {
    printf("no remote fingerprint\n");
    return -1;
  }

  return ret;
}

void dtls_reset_session(dtls_context_t *dtls) {
  if (dtls->state == DTLS_STATE_CONNECTED) {
    mbedtls_ssl_session_reset(&dtls->ssl);
  }
  dtls->state = DTLS_STATE_INIT;
}

int dtls_write(dtls_context_t *dtls, const unsigned char* buf, size_t len) {
  int ret;

  do {
    ret = mbedtls_ssl_write(&dtls->ssl, buf, len);

  } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
  return ret;
}

int dtls_read(dtls_context_t *dtls, unsigned char* buf, size_t len) {
  int ret;

  memset(buf, 0, len);

  do {
    ret = mbedtls_ssl_read(&dtls->ssl, buf, len);

  } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  return ret;
}

int dtls_probe(uint8_t* buf) {
  if (buf == NULL)
    return 0;

  printf("DTLS content type: %d", buf[0]);
  return (buf[0] == 0x17);
}

int gen_key_pair(mbedtls_pk_context *pkey, const char *key_type, int key_size) 
{
    int ret = 0;
    const char *pers = "mbedtls_pk_genkey"; //

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0) {
        printf("Failed to initialize CTR_DRBG\n");
        goto cleanup;
    }

    if (strcmp(key_type, "rsa") == 0) {
        if ((ret = mbedtls_pk_setup(pkey, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) != 0) {
            printf("Failed to setup PK context\n");
            goto cleanup;
        }

        if ((ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(*pkey), mbedtls_ctr_drbg_random, &ctr_drbg, key_size, 65537)) != 0) {
            printf("Failed to generate RSA key\n");
            goto cleanup;
        }

    } else if (strcmp(key_type, "ecc") == 0) {
        if ((ret = mbedtls_pk_setup(pkey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) != 0) {
            printf("Failed to setup PK context\n");
            goto cleanup;
        }

        char curve_name[10];
        snprintf(curve_name, sizeof(curve_name), "secp%dr1", key_size);

        const mbedtls_ecp_curve_info *curve_info = mbedtls_ecp_curve_info_from_name(curve_name);
        if (curve_info == NULL) {
            printf("Invalid curve name: %s\n", curve_name);
            ret = -1;
            goto cleanup;
        }

        if ((ret = mbedtls_ecp_gen_key(curve_info->grp_id, mbedtls_pk_ec(*pkey),
                                       mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
            printf("Failed to generate ECC key\n");
            goto cleanup;
        }

    } else {
        printf("Invalid key type specified: %s\n", key_type);
        ret = -1;
        goto cleanup;
    }

cleanup:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}


int write_private_key(mbedtls_pk_context *pkey, const char *format, const char *file_name)
{
    int ret;
    FILE *f = fopen(file_name, "wb");
    if (!f) {
        perror("Failed to open output file");
        ret = 1;
        goto cleanup;
    }

    if (strcmp(format, "pem") == 0) {
        unsigned char pem_buffer[4096]; 
        if ((ret = mbedtls_pk_write_key_pem(pkey, pem_buffer, sizeof(pem_buffer))) != 0) {
            printf("Failed to write private key in PEM format\n");
            fclose(f);
            goto cleanup;
        }

        fwrite(pem_buffer, 1, strlen((char *)pem_buffer), f);
    } else { 
        unsigned char buf[4096];
        if ((ret = mbedtls_pk_write_key_der(pkey, buf, sizeof(buf))) < 0) {
            printf("Failed to write private key in DER format\n");
            fclose(f);
            goto cleanup;
        }

        fwrite(buf + sizeof(buf) - ret, 1, ret, f);
    }

    fclose(f);
    printf("Key written to %s\n", file_name);
    ret = 0;

cleanup:
    return ret;
}

int write_public_key(mbedtls_pk_context *pkey, const char *format, const char *file_name)
{
    int ret;
    FILE *f = fopen(file_name, "wb");
    if (!f) {
        perror("Failed to open output file");
        ret = 1;
        goto cleanup;
    }

    if (strcmp(format, "pem") == 0) {
        unsigned char pem_buffer[4096]; 
        if ((ret = mbedtls_pk_write_pubkey_pem(pkey, pem_buffer, sizeof(pem_buffer))) != 0) {
            printf("Failed to write key in PEM format\n");
            fclose(f);
            goto cleanup;
        }

        fwrite(pem_buffer, 1, strlen((char *)pem_buffer), f);
    } else { 
        unsigned char buf[4096];
        if ((ret = mbedtls_pk_write_pubkey_der(pkey, buf, sizeof(buf))) < 0) {
            printf("Failed to write key in DER format");
            fclose(f);
            goto cleanup;
        }
        fwrite(buf + sizeof(buf) - ret, 1, ret, f);
    }

    fclose(f);
    printf("Key written to %s\n", file_name);
    ret = 0;

cleanup:
    return ret;
}


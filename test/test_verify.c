#include "mbedtls/platform.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
    if (argc != 3) {
        mbedtls_printf("Usage: %s <key_file> <input_file>\n", argv[0]);
        return 1;
    }

    mbedtls_pk_context pk;
    unsigned char hash[32], buf[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    size_t sig_len;
    char sig_file[512];

    mbedtls_pk_init(&pk);

    if (mbedtls_pk_parse_public_keyfile(&pk, argv[1]) != 0) {
        mbedtls_printf("Failed to load public key\n");
        return 1;
    }

    snprintf(sig_file, sizeof(sig_file), "%s.sig", argv[2]);
    FILE *f = fopen(sig_file, "rb");
    if (!f) {
        mbedtls_printf("Failed to open signature file\n");
        return 1;
    }
    printf("signature file: %s\n", sig_file);
    sig_len = fread(buf, 1, sizeof(buf), f);
    fclose(f);


    if (mbedtls_md_file(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), argv[2], hash) != 0) {
        mbedtls_printf("Failed to compute hash\n");
        return 1;
    }

    if (mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 0, buf, sig_len) != 0) {
        mbedtls_printf("Signature verification failed\n");
        return 1;
    }

    mbedtls_printf("Signature is valid\n");

    mbedtls_pk_free(&pk);
    return 0;
}

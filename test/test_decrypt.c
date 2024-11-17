#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    FILE *f;
    int ret = 1;
    size_t i, olen = 0;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char result[1024];
    unsigned char buf[512];
    unsigned c;
    const char *pers = "mbedtls_pk_decrypt";

    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if (argc != 2) {
        printf("usage: mbedtls_pk_decrypt <key_file>\n");
        goto exit;
    }

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 
                                     (const unsigned char *) pers, strlen(pers))) != 0) {
        printf(" failed\n  ! mbedtls_ctr_drbg_seed returned\n");
        goto exit;
    }

    if ((ret = mbedtls_pk_parse_keyfile(&pk, argv[1], "", mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
        printf(" failed\n  ! mbedtls_pk_parse_keyfile returned\n");
        goto exit;
    }

    if ((f = fopen("result-enc.txt", "rb")) == NULL) {
        printf("\n  ! Could not open %s\n\n", "result-enc.txt");
        ret = 1;
        goto exit;
    }

    i = 0;
    while (fscanf(f, "%02X", (unsigned int *) &c) > 0 && i < sizeof(buf)) {
        buf[i++] = (unsigned char) c;
    }

    fclose(f);

    if ((ret = mbedtls_pk_decrypt(&pk, buf, i, result, &olen, sizeof(result), 
                                  mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
        printf(" failed\n  ! mbedtls_pk_decrypt returned\n");
        goto exit;
    }

    printf("Decrypted result: '%s'\n", result);

    ret = 0;

exit:
    mbedtls_pk_free(&pk);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    return ret;
}

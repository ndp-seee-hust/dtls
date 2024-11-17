#include "mbedtls/platform.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
    if (argc != 3) {
        mbedtls_printf("usage: mbedtls_pk_encrypt <key_file> <string of max 100 characters>\n");
        return 1;
    }

    int ret;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char input[1024], buf[512];
    size_t olen = 0;

    const char *pers = "mbedtls_pk_encrypt";

    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_printf("Seeding RNG...\n");
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers))) != 0) {
        mbedtls_printf("RNG seed failed: -0x%04x\n", -ret);
        return 1;
    }

    mbedtls_printf("Reading public key...\n");
    if ((ret = mbedtls_pk_parse_public_keyfile(&pk, argv[1])) != 0) {
        mbedtls_printf("Failed to parse public key: -0x%04x\n", -ret);
        return 1;
    }

    if (strlen(argv[2]) > 100) {
        mbedtls_printf("Input data exceeds 100 characters\n");
        return 1;
    }

    memcpy(input, argv[2], strlen(argv[2]));

    mbedtls_printf("Encrypting data...\n");
    if ((ret = mbedtls_pk_encrypt(&pk, input, strlen(argv[2]), buf, &olen, sizeof(buf), mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
        mbedtls_printf("Encryption failed: -0x%04x\n", -ret);
        return 1;
    }

    FILE *f = fopen("result-enc.txt", "wb+");
    if (!f) {
        mbedtls_printf("Failed to create result-enc.txt\n");
        return 1;
    }

    for (size_t i = 0; i < olen; i++) {
        mbedtls_fprintf(f, "%02X%s", buf[i], (i + 1) % 16 == 0 ? "\r\n" : " ");
    }

    fclose(f);
    mbedtls_printf("Done (created \"result-enc.txt\")\n");

    mbedtls_pk_free(&pk);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    return 0;
}

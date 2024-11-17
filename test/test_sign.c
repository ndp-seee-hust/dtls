#include "mbedtls/platform.h"
#include "mbedtls/md.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
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
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char hash[32], buf[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    const char *pers = "mbedtls_pk_sign";
    size_t olen;
    char sig_file[512];

    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 
                              (const unsigned char *)pers, strlen(pers)) != 0) {
        mbedtls_printf("Failed to seed RNG\n");
        return 1;
    }

    if (mbedtls_pk_parse_keyfile(&pk, argv[1], NULL, mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
        mbedtls_printf("Failed to load private key\n");
        return 1;
    }

    if (mbedtls_md_file(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), argv[2], hash) != 0) {
        mbedtls_printf("Failed to compute SHA-256 hash\n");
        return 1;
    }

    if (mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, 0, buf, sizeof(buf), &olen,
                        mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
        mbedtls_printf("Failed to sign hash\n");
        return 1;
    }

    snprintf(sig_file, sizeof(sig_file), "%s.sig", argv[2]);
    FILE *f = fopen(sig_file, "wb");
    if (!f || fwrite(buf, 1, olen, f) != olen) {
        mbedtls_printf("Failed to write signature\n");
        return 1;
    }
    fclose(f);

    mbedtls_printf("Signature written to %s\n", sig_file);

    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return 0;
}

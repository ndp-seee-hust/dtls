#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>

void print_usage(const char *prog_name) {
    printf("Usage: %s -keysize=<size> -format=<pem|der> -file=<output_file>\n", prog_name);
}

int main(int argc, char *argv[]) {
    int keysize = 0;
    char format[4] = {0}; 
    char output_file[256] = {0};


    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "-keysize=", 9) == 0) {
            keysize = atoi(argv[i] + 9);
        } else if (strncmp(argv[i], "-format=", 8) == 0) {
            strncpy(format, argv[i] + 8, sizeof(format) - 1);
        } else if (strncmp(argv[i], "-file=", 6) == 0) {
            strncpy(output_file, argv[i] + 6, sizeof(output_file) - 1);
        }
    }

    if (keysize <= 0 || (strcmp(format, "pem") != 0 && strcmp(format, "der") != 0) || strlen(output_file) == 0) {
        print_usage(argv[0]);
        return 1;
    }

    int ret;
    mbedtls_pk_context pk;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    const char *pers = "gen_rsa_key";

    mbedtls_pk_init(&pk);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 
                                     (const unsigned char *) pers, strlen(pers))) != 0) {
        fprintf(stderr, "Failed to seed RNG: -0x%04x\n", -ret);
        goto cleanup;
    }

    if ((ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) != 0) {
        fprintf(stderr, "Failed to setup PK context: -0x%04x\n", -ret);
        goto cleanup;
    }

    if ((ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk), mbedtls_ctr_drbg_random, &ctr_drbg, keysize, 65537)) != 0) {
        fprintf(stderr, "Failed to generate RSA key: -0x%04x\n", -ret);
        goto cleanup;
    }

    FILE *f = fopen(output_file, "wb");
    if (!f) {
        perror("Failed to open output file");
        ret = 1;
        goto cleanup;
    }

    if (strcmp(format, "pem") == 0) {
        unsigned char pem_buffer[4096]; 
        if ((ret = mbedtls_pk_write_key_pem(&pk, pem_buffer, sizeof(pem_buffer))) != 0) {
            fprintf(stderr, "Failed to write key in PEM format: -0x%04x\n", -ret);
            fclose(f);
            goto cleanup;
        }

        fwrite(pem_buffer, 1, strlen((char *)pem_buffer), f);
    } else { // der format
        unsigned char buf[4096];
        if ((ret = mbedtls_pk_write_key_der(&pk, buf, sizeof(buf))) < 0) {
            fprintf(stderr, "Failed to write key in DER format: -0x%04x\n", -ret);
            fclose(f);
            goto cleanup;
        }

        fwrite(buf + sizeof(buf) - ret, 1, ret, f);
    }

    fclose(f);
    printf("Key written to %s\n", output_file);
    ret = 0;

cleanup:
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

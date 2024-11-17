#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/pk.h"
#include "mbedtls/error.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

void print_mbedtls_error(int ret) {
    char error_buf[100];
    mbedtls_strerror(ret, error_buf, sizeof(error_buf));
    fprintf(stderr, "Error: %s\n", error_buf);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s -curve=<curve_name> -format=<pem|der> -file=<output_file>\n", argv[0]);
        return 1;
    }

    char *curve_name = NULL;
    char *file_name = NULL;
    char *format = NULL;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "-curve=", 7) == 0) {
            curve_name = argv[i] + 7;
        } else if (strncmp(argv[i], "-file=", 6) == 0) {
            file_name = argv[i] + 6;
        } else if (strncmp(argv[i], "-format=", 8) == 0) {
            format = argv[i] + 8;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            return 1;
        }
    }

    if (!curve_name || !file_name || !format) {
        fprintf(stderr, "Missing required arguments.\n");
        return 1;
    }

    int ret;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    FILE *f;

    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0) {
        fprintf(stderr, "Failed to seed random number generator: -0x%04x\n", -ret);
        print_mbedtls_error(ret);
        goto cleanup;
    }

    if ((ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) != 0) {
        fprintf(stderr, "Failed to setup PK context: -0x%04x\n", -ret);
        print_mbedtls_error(ret);
        goto cleanup;
    }

    const mbedtls_ecp_curve_info *curve_info = mbedtls_ecp_curve_info_from_name(curve_name);
    if (curve_info == NULL) {
        fprintf(stderr, "Invalid curve name: %s\n", curve_name);
        goto cleanup;
    }

    if ((ret = mbedtls_ecp_gen_key(curve_info->grp_id, mbedtls_pk_ec(pk), 
                                   mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
        fprintf(stderr, "Failed to generate ECC key: -0x%04x\n", -ret);
        print_mbedtls_error(ret);
        goto cleanup;
    }

    if ((f = fopen(file_name, "wb")) == NULL) {
        fprintf(stderr, "Failed to open output file: %s\n", file_name);
        goto cleanup;
    }

    if (strcmp(format, "pem") == 0) {
        unsigned char pem_buffer[4096];
        if ((ret = mbedtls_pk_write_key_pem(&pk, pem_buffer, sizeof(pem_buffer))) != 0) {
            fprintf(stderr, "Failed to write key in PEM format: -0x%04x\n", -ret);
            print_mbedtls_error(ret);
            fclose(f);
            goto cleanup;
        }
        fwrite(pem_buffer, 1, strlen((char *)pem_buffer), f);
    } else if (strcmp(format, "der") == 0) {
        unsigned char der_buffer[4096];
        ret = mbedtls_pk_write_key_der(&pk, der_buffer, sizeof(der_buffer));
        if (ret < 0) {
            fprintf(stderr, "Failed to write key in DER format: -0x%04x\n", -ret);
            print_mbedtls_error(ret);
            fclose(f);
            goto cleanup;
        }
        fwrite(der_buffer + sizeof(der_buffer) - ret, 1, ret, f);
    } else {
        fprintf(stderr, "Invalid format: %s\n", format);
        fclose(f);
        goto cleanup;
    }

    fclose(f);
    printf("ECC key successfully generated and written to %s\n", file_name);

cleanup:
    mbedtls_pk_free(&pk);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    return ret == 0 ? 0 : 1;
}

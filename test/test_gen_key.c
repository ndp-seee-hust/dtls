#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "dtls.h"


int main(int argc, char *argv[])
{
    clock_t start, end;
    double time_exc;

    if (argc != 6) {
        printf("Usage: %s <key_type> <key_size> <format> <private_key_file> <public_key_file>\n", argv[0]);
        printf("Example: %s rsa 2048 pem rsa_prikey.pem rsa_pubkey.pem\n", argv[0]);
        printf("         %s ecc 256 der ecc_prikey.der ecc_pubkey.der\n", argv[0]);
        return -1;
    }

    const char *key_type = argv[1];
    int key_size = atoi(argv[2]);
    const char *format = argv[3];
    const char *prikey_file_name = argv[4];
    const char *pubkey_file_name = argv[5];

    mbedtls_pk_context pkey;
    mbedtls_pk_init(&pkey);

    start = clock();

    int ret = gen_key_pair(&pkey, key_type, key_size);

    end = clock();

    if (ret != 0) {
        printf("Error generating key\n");
        mbedtls_pk_free(&pkey);
        return ret;
    }else{
        printf("Generate %s %d key successfully\n", key_type, key_size);
    }

    time_exc = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Elapsed time: %.6f seconds\n", time_exc);
    
    ret = write_private_key(&pkey, format, prikey_file_name);
    if (ret != 0) {
        printf("Error writing key to file\n");
    }

    ret = write_public_key(&pkey, format, pubkey_file_name);
    if (ret != 0) {
        printf("Error writing key to file\n");
    }

    mbedtls_pk_free(&pkey);
    return ret;
}
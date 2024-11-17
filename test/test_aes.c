#include <stdio.h>
#include <string.h>
#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <mbedtls/platform.h>

#define AES_BLOCK_SIZE 16
#define KEY_SIZE 16

void handle_error(int ret) {
    if (ret != 0) {
        printf("Failed: %d\n", ret);
        exit(ret);
    }
}

void aes_encrypt(const unsigned char *input, unsigned char *output, const unsigned char *key) {
    mbedtls_aes_context aes;
    int ret;

    mbedtls_aes_init(&aes);

    ret = mbedtls_aes_setkey_enc(&aes, key, 128);
    handle_error(ret);

    ret = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, input, output);
    handle_error(ret);

    mbedtls_aes_free(&aes);
}

void aes_decrypt(const unsigned char *input, unsigned char *output, const unsigned char *key) {
    mbedtls_aes_context aes;
    int ret;

    mbedtls_aes_init(&aes);

    ret = mbedtls_aes_setkey_dec(&aes, key, 128);
    handle_error(ret);

    ret = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, input, output);
    handle_error(ret);

    mbedtls_aes_free(&aes);
}

void hash_data(const unsigned char *input, size_t len, unsigned char *output) {
    mbedtls_md_context_t md_ctx;
    const mbedtls_md_info_t *md_info;
    int ret;

    mbedtls_md_init(&md_ctx);

    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256); // hash function: SHA256
    ret = mbedtls_md_setup(&md_ctx, md_info, 0);
    handle_error(ret);

    ret = mbedtls_md_starts(&md_ctx);
    handle_error(ret);

    ret = mbedtls_md_update(&md_ctx, input, len);
    handle_error(ret);

    ret = mbedtls_md_finish(&md_ctx, output);
    handle_error(ret);

    mbedtls_md_free(&md_ctx);
}

int main() {
    unsigned char key[KEY_SIZE] = "0123456789abcdef"; 
    unsigned char input[] = "Hello, World!"; 
    unsigned char output[AES_BLOCK_SIZE];
    unsigned char hash_output[32]; // (SHA-256)

    printf("Plaintext: %s\n", input);

    aes_encrypt(input, output, key);
    printf("Encrypted data: ");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");

    unsigned char decrypted[AES_BLOCK_SIZE];
    aes_decrypt(output, decrypted, key);
    printf("Decrypted: %s\n", decrypted);

    hash_data(input, strlen((char *)input), hash_output);
    printf("Hash SHA-256: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash_output[i]);
    }
    printf("\n");

    return 0;
}

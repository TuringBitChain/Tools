#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

// 用于错误处理
#define HANDLE_ERROR(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while (0)

// 解码 Base64 字符串
unsigned char *base64_decode(const char *base64data, size_t *out_len) {
    BIO *bio, *b64;
    size_t decode_len = strlen(base64data) * 3 / 4;
    unsigned char *buffer = (unsigned char *)malloc(decode_len + 1);
    if (buffer == NULL) {
        HANDLE_ERROR("malloc");
    }

    bio = BIO_new_mem_buf(base64data, -1);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    *out_len = BIO_read(bio, buffer, strlen(base64data));
    buffer[*out_len] = '\0';

    BIO_free_all(bio);
    return buffer;
}

// 编码 Base64 字符串
char *base64_encode(const unsigned char *input, int length) {
    BIO *bmem, *b64;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    char *buff = (char *)malloc(bptr->length + 1);
    if (buff == NULL) {
        HANDLE_ERROR("malloc");
    }
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = '\0';

    BIO_free_all(b64);
    return buff;
}

// 使用 PBKDF2 生成密钥
void generate_key(const char *password, unsigned char *salt, unsigned char *key) {
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, 16, 1000000, EVP_sha256(), 32, key)) {
        HANDLE_ERROR("PKCS5_PBKDF2_HMAC");
    }
}

// 使用 AES 加密私钥
char *encrypt_private_key(unsigned char *private_key, const char *password, int private_key_len) {
    unsigned char salt[16], iv[16], key[32];
    if (!RAND_bytes(salt, sizeof(salt)) || !RAND_bytes(iv, sizeof(iv))) {
        HANDLE_ERROR("RAND_bytes");
    }

    generate_key(password, salt, key);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;
    unsigned char ciphertext[128];  // 足够大的缓冲区来存储加密的私钥

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, key, iv)) {
        HANDLE_ERROR("EVP_EncryptInit_ex");
    }

    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, private_key, private_key_len)) {
        HANDLE_ERROR("EVP_EncryptUpdate");
    }
    ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        HANDLE_ERROR("EVP_EncryptFinal_ex");
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    unsigned char *encrypted_data = (unsigned char *)malloc(32 + ciphertext_len);
    if (encrypted_data == NULL) {
        HANDLE_ERROR("malloc");
    }
    memcpy(encrypted_data, salt, 16);
    memcpy(encrypted_data + 16, iv, 16);
    memcpy(encrypted_data + 32, ciphertext, ciphertext_len);

    char *base64_encrypted = base64_encode(encrypted_data, 32 + ciphertext_len);
    free(encrypted_data);
    return base64_encrypted;
}

// 使用 AES 解密私钥
int decrypt_private_key(unsigned char *encrypted_data, size_t encrypted_len, const char *password, unsigned char *decrypted_key) {
    unsigned char salt[16], iv[16], key[32];
    unsigned char *ciphertext = encrypted_data + 32;
    size_t ciphertext_len = encrypted_len - 32;

    memcpy(salt, encrypted_data, 16);
    memcpy(iv, encrypted_data + 16, 16);

    // 使用 PBKDF2 从密码和盐生成密钥
    generate_key(password, salt, key);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, key, iv)) {
        HANDLE_ERROR("EVP_DecryptInit_ex");
    }

    if (!EVP_DecryptUpdate(ctx, decrypted_key, &len, ciphertext, ciphertext_len)) {
        HANDLE_ERROR("EVP_DecryptUpdate");
    }
    plaintext_len = len;

    if (!EVP_DecryptFinal_ex(ctx, decrypted_key + len, &len)) {
        HANDLE_ERROR("EVP_DecryptFinal_ex");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

// 生成 Bitcoin 私钥和压缩公钥
void generate_bitcoin_keys(unsigned char **private_key, int *private_key_len, unsigned char **compressed_public_key, int *compressed_public_key_len) {
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (eckey == NULL) {
        HANDLE_ERROR("EC_KEY_new_by_curve_name");
    }

    if (!EC_KEY_generate_key(eckey)) {
        HANDLE_ERROR("EC_KEY_generate_key");
    }

    const BIGNUM *priv_bn = EC_KEY_get0_private_key(eckey);
    *private_key_len = BN_num_bytes(priv_bn);
    *private_key = (unsigned char *)malloc(*private_key_len);
    if (*private_key == NULL) {
        HANDLE_ERROR("malloc");
    }
    BN_bn2bin(priv_bn, *private_key);

    // 生成压缩公钥
    EC_KEY_set_conv_form(eckey, POINT_CONVERSION_COMPRESSED);
    *compressed_public_key_len = i2o_ECPublicKey(eckey, compressed_public_key);
    if (*compressed_public_key_len == 0) {
        HANDLE_ERROR("i2o_ECPublicKey (compressed)");
    }

    EC_KEY_free(eckey);
}

int main() {
    unsigned char *private_key = NULL;
    unsigned char *compressed_public_key = NULL;
    int private_key_len, compressed_public_key_len;

    generate_bitcoin_keys(&private_key, &private_key_len, &compressed_public_key, &compressed_public_key_len);

    printf("KYC private key: ");
    for (int i = 0; i < private_key_len; i++) {
        printf("%02x", private_key[i]);
    }
    printf("\n");

    printf("KYC public key: ");
    for (int i = 0; i < compressed_public_key_len; i++) {
        printf("%02x", compressed_public_key[i]);
    }
    printf("\n");

    char password[128];
    printf("Enter your encrypt password: ");
    scanf("%127s", password);

    char *encrypted_private_key = encrypt_private_key(private_key, password, private_key_len);
    printf("Encrypted KYC private key: %s\n", encrypted_private_key);

    // // 解密私钥
    // size_t encrypted_len;
    // unsigned char *encrypted_data = base64_decode(encrypted_private_key, &encrypted_len);

    // unsigned char decrypted_key[32];  // 足够大的缓冲区来存储解密后的私钥
    // int decrypted_len = decrypt_private_key(encrypted_data, encrypted_len, password, decrypted_key);

    // if (decrypted_len == 32) {
    //     printf("Decrypted private key: ");
    //     for (int i = 0; i < decrypted_len; i++) {
    //         printf("%02x", decrypted_key[i]);
    //     }
    //     printf("\n");

    //     if (decrypted_len == private_key_len && memcmp(private_key, decrypted_key, private_key_len) == 0) {
    //         printf("The decrypted private key matches the original.\n");
    //     } else {
    //         printf("The decrypted private key does not match the original.\n");
    //     }
    // } else {
    //     printf("Decryption failed or unexpected length: %d bytes\n", decrypted_len);
    // }

    // 清理
    free(private_key);
    OPENSSL_free(compressed_public_key);
    free(encrypted_private_key);
    //free(encrypted_data);

    return 0;
}

#include<stdio.h>
#include<openssl/evp.h>

unsigned char* derive_aes_key(unsigned char *secret, size_t secret_len)
{
    unsigned char *result = malloc(32);
    unsigned int result_len;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL); // EVP_sha256 : 어떤 데이터든 32바이트로 압축하는 함수 
    EVP_DigestUpdate(ctx, secret, secret_len); 
    EVP_DigestFinal(ctx, result, &result_len);    
    EVP_MD_CTX_free(ctx);

    return result;
}

unsigned char* aes_enc(unsigned char *key, unsigned char *plaintext, int plaintext_len, int *cipertext_len)
{
    unsigned char iv[16];
    RAND_bytes(iv, 16);

    unsigned char *result = malloc(16 + plaintext_len + 16);
    unsigned int result_len;
    unsigned int p_len;

    memcpy(result, iv, 16);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, result+16, &result_len, plaintext, plaintext_len);
    EVP_EncryptFinal_ex(ctx, result + result_len + 16, &p_len);
    EVP_CIPHER_CTX_free(ctx);

    *ciphertext_len = p_len + result_len + 16; 

    return result;
}

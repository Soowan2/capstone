#include"AES.h"

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

unsigned char* aes_enc(unsigned char *key, unsigned char *plaintext, int plaintext_len, int *ciphertext_len)
{
    unsigned char iv[12];
    RAND_bytes(iv, 12);

    unsigned char *result = malloc(12 + plaintext_len + 16);
    unsigned int result_len;
    unsigned int p_len;
    unsigned char tag[16];
    
    memcpy(result, iv, 12);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, result+12, &result_len, plaintext, plaintext_len);
    EVP_EncryptFinal_ex(ctx, result + result_len + 12, &p_len); // 패딩 크기 계산
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    memcpy(result + 12 + result_len + p_len, tag, 16);
    EVP_CIPHER_CTX_free(ctx);

    *ciphertext_len = p_len + result_len + 12 + 16; 

    return result;
}

unsigned char* aes_dec(unsigned char* key, unsigned char* ciphertext, int ciphertext_len, int *plaintext_len)
{
    unsigned char *result = malloc(ciphertext_len);
    unsigned int result_len;
    unsigned int final_len;
    unsigned char* iv = ciphertext; 
    unsigned char* tag = ciphertext + ciphertext_len -16;
    int enc_len = ciphertext_len - 16 - 12; // 순수 암호문 길이
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx,EVP_aes_256_gcm(),NULL,key,iv);
    EVP_DecryptUpdate(ctx, result, &result_len, ciphertext + 12, enc_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    int ret = EVP_DecryptFinal_ex(ctx, result + result_len, &final_len); // 마지막 블록에서 패딩을 제외한 길이
    if (ret <= 0) {
        printf("tag 변조됨\n");
    }
    EVP_CIPHER_CTX_free(ctx);

    *plaintext_len = result_len + final_len;

    return result;
}

#include <stdio.h>
#include "DH.h"
#include "AES.h"

int main()
{
    // 1. DH 키 교환
    EVP_PKEY *pg = generate_pg();
    EVP_PKEY *ALICE = generate_user(pg);
    EVP_PKEY *BOB = generate_user(pg);

    size_t secret_len;
    unsigned char *secret = generate_secret(ALICE, BOB, &secret_len);

    printf("공유비밀 생성 완료 (%zu bytes)\n", secret_len);

    // 2. SHA-256으로 AES 키 생성
    unsigned char *aes_key = derive_aes_key(secret, secret_len);

    printf("AES 키 생성 완료: ");
    for (int i = 0; i < 32; i++) printf("%02x", aes_key[i]);
    printf("\n");

    // 3. 암호화
    char *message = "Hello NexSH!";
    int ciphertext_len;
    unsigned char *encrypted = aes_enc(aes_key, (unsigned char*)message, strlen(message), &ciphertext_len);

    printf("암호문 (%d bytes): ", ciphertext_len);
    for (int i = 0; i < ciphertext_len; i++) printf("%02x", encrypted[i]);
    printf("\n");

    // 4. 복호화
    int plaintext_len;
    unsigned char *decrypted = aes_dec(aes_key, encrypted, ciphertext_len, &plaintext_len);

    printf("복호화 결과: %.*s\n", plaintext_len, decrypted);

    // 5. 메모리 해제
    free(secret);
    free(aes_key);
    free(encrypted);
    free(decrypted);
    EVP_PKEY_free(pg);
    EVP_PKEY_free(ALICE);
    EVP_PKEY_free(BOB);

    return 0;
}

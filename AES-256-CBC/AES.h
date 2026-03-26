#ifndef AES_H
#define AES_H
#include<stdio.h>
#include<string.h>
#include<openssl/evp.h>
#include<openssl/rand.h>


unsigned char* derive_aes_key(unsigned char *secret, size_t secret_len);
unsigned char* aes_enc(unsigned char *key, unsigned char *plaintext, int plaintext_len, int *ciphertext_len);
unsigned char* aes_dec(unsigned char* key, unsigned char* ciphertext, int ciphertext_len, int *plaintext_len);

#endif
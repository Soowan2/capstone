#ifndef SW
#define SW

#include<stdlib.h>
#include<openssl/evp.h>
#include <openssl/dh.h>

EVP_PKEY* generate_pg();
EVP_PKEY* generate_user(EVP_PKEY* pg);
unsigned char* generate_secret(EVP_PKEY* ALICE, EVP_PKEY* BOB, size_t *secret_len);
unsigned char* send_pk(EVP_PKEY *key, int *len);
EVP_PKEY* recv_pk(unsigned char* data, int len);
unsigned char* send_pg(EVP_PKEY *pg,int *len);
EVP_PKEY *recv_pg(unsigned char* data, int len);

#endif
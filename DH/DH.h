#ifndef SW
#define SW

#include<stdlib.h>
#include<openssl/evp.h>

EVP_PKEY* generate_pg();
EVP_PKEY* generate_user(EVP_PKEY* pg);
unsigned char* generate_secret(EVP_PKEY* ALICE, EVP_PKEY* BOB, size_t *secret_len);

#endif
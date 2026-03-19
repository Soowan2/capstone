#include <stdio.h>
#include "DH.h"

int main()
{
    EVP_PKEY *pg = generate_pg();
    EVP_PKEY *ALICE = generate_user(pg);
    EVP_PKEY *BOB = generate_user(pg);

    size_t len1, len2;
    unsigned char *secret1 = generate_secret(ALICE, BOB, &len1);
    unsigned char *secret2 = generate_secret(BOB, ALICE, &len2);

    printf("ALICE: ");
    for (int i = 0; i < len1; i++) printf("%02x", secret1[i]);
    printf("\n");

    printf("BOB:   ");
    for (int i = 0; i < len2; i++) printf("%02x", secret2[i]);
    printf("\n");

    free(secret1);
    free(secret2);
    EVP_PKEY_free(pg);
    EVP_PKEY_free(ALICE);
    EVP_PKEY_free(BOB);
}

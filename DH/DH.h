#include<stdio.h>
#include<openssl/evp.h>
#include<openssl/dh.h>

//pg 생성함수
//alice bob 생성함수
//내키 상대방 키 길이 저장함수

EVP_PKEY* generate_pg()
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pg = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH,NULL);
    EVP_PKEY_paramgen_init(ctx); // 초기화
    EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, 2048); // p의 크기를 2048비트로 지정 : 안해도 똑같네;
    EVP_PKEY_paramgen(ctx,&pg);
    EVP_PKEY_CTX_free(ctx); // 메모리 누수 방지

    return pg;
}

EVP_PKEY* generate_user(EVP_PKEY* pg)
{
    EVP_PKEY_CTX *ctx_user;
    EVP_PKEY* USER = NULL;
    
    ctx_user = EVP_PKEY_CTX_new(pg,NULL);
    EVP_PKEY_keygen_init(ctx_user);
    EVP_PKEY_keygen(ctx_user,&USER);
    EVP_PKEY_CTX_free(ctx_user);

    return USER;
}


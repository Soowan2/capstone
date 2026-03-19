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

unsigned char* generate_secret(EVP_PKEY* ALICE, EVP_PKEY* BOB, size_t *secret_len)
{
    EVP_PKEY_CTX *ctx_exchange;

    ctx_exchange = EVP_PKEY_CTX_new(ALICE, NULL); // ctx_exchange에 ALICE의 공개키, 비밀키를 집어넣음
    EVP_PKEY_derive_init(ctx_exchange); //초기화
    EVP_PKEY_derive_set_peer(ctx_exchange, BOB); // ctx_exchange에 BOB의 공개키를 집어넣음
    EVP_PKEY_derive(ctx_exchange,NULL,secret_len); // secret_len 길이 지정

    unsigned char* secret = malloc(*secret_len); // 비밀키 변수 생성
    EVP_PKEY_derive(ctx_exchange,secret,secret_len);
    EVP_PKEY_CTX_free(ctx_exchange);

    return secret;
}
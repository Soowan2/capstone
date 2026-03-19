#include<stdio.h>
#include<openssl/evp.h>
#include<openssl/dh.h>
#include <openssl/bio.h> // ALICE의 비밀키, 공유키를 확인하기위한 헤더파일 
/*
EVP_PKEY_CTX = 키 생성 컨텍스트
EVP_PKEY_paramen = DH파라미터 생성
EVP_PKEY_keygen = 키 생성
EVP_PKEY_derive = 공유 비밀 계산
*/



int main()
{
    EVP_PKEY_CTX *ctx; //pg값 작업대
    EVP_PKEY_CTX *ctx_alice; // alice 작업대
    EVP_PKEY_CTX *ctx_bob; // bob 작업대
    EVP_PKEY_CTX *ctx_exchange; // 키 교환 작업대
    EVP_PKEY *pg = NULL;
    EVP_PKEY *ALICE = NULL;
    EVP_PKEY *BOB = NULL;
    size_t secret_len; 


    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL); //ctx에 DH 작업 할 틀 마련

    EVP_PKEY_paramgen_init(ctx); //ctx
    EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, 2048); // p의 크기를 2048비트로 지정 : 안해도 똑같네;
    EVP_PKEY_paramgen(ctx,&pg);
    EVP_PKEY_CTX_free(ctx); // 메모리 누수 방지

    ctx_alice = EVP_PKEY_CTX_new(pg,NULL); // alice를 만들 작업대 설정
    EVP_PKEY_keygen_init(ctx_alice); // ctx_alice 초기화 : 왜 필요한가?
    EVP_PKEY_keygen(ctx_alice,&ALICE);
    EVP_PKEY_CTX_free(ctx_alice); // 메모리 누수 방지

    ctx_bob = EVP_PKEY_CTX_new(pg,NULL);
    EVP_PKEY_keygen_init(ctx_bob);
    EVP_PKEY_keygen(ctx_bob,&BOB);
    EVP_PKEY_CTX_free(ctx_bob);

    ctx_exchange = EVP_PKEY_CTX_new(ALICE, NULL); // ctx_exchange에 ALICE의 공개키, 비밀키를 집어넣음
    EVP_PKEY_derive_init(ctx_exchange); //초기화
    EVP_PKEY_derive_set_peer(ctx_exchange, BOB); // ctx_exchange에 BOB의 공개키를 집어넣음
    EVP_PKEY_derive(ctx_exchange,NULL,&secret_len); // secret_len 길이 지정

    unsigned char* secret = malloc(secret_len); // 비밀키 변수 생성

    EVP_PKEY_derive(ctx_exchange,secret,&secret_len);
    EVP_PKEY_CTX_free(ctx_exchange);

    printf("ALICE secret : [%zu bytes]\n",secret_len);
    printf("ALICE secret : ");
    for(int i = 0;i < secret_len; i++)
    {
        printf("%02x",secret[i]);
    }
    printf("\n");

    ctx_exchange = EVP_PKEY_CTX_new(BOB, NULL); 
    EVP_PKEY_derive_init(ctx_exchange); //초기화
    EVP_PKEY_derive_set_peer(ctx_exchange, ALICE); 
    EVP_PKEY_derive(ctx_exchange,NULL,&secret_len); 

    unsigned char* secret2 = malloc(secret_len); // 비밀키 변수 생성

    EVP_PKEY_derive(ctx_exchange,secret2,&secret_len);
    EVP_PKEY_CTX_free(ctx_exchange);
    
    printf("BOB secret : [%zu bytes]\n",secret_len);
    printf("BOB secret : ");
    for(int i = 0;i < secret_len; i++)
    {
        printf("%02x",secret2[i]);
    }
    printf("\n");
}
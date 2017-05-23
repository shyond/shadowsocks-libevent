#ifndef  _ENCRYPT_H
#define  _ENCRYPT_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "utils.h"



#ifdef max
#undef max
#endif

#ifdef min
#undef min
#endif


#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))
//#define abs(a) ((a < 0) ? (-a) : (a))


//use openssl lib
#if defined(USE_CRYPTO_OPENSSL)

#include <openssl/evp.h>
typedef EVP_CIPHER  cipher_kt_t;
typedef EVP_CIPHER_CTX cipher_evp_t;
typedef EVP_MD digest_type_t;
#define  MAX_KEY_LENGTH EVP_MAX_KEY_LENGTH
#define  MAX_IV_LENGTH  EVP_MAX_IV_LENGTH
#define  MAX_MD_SIZE    EVP_MAX_MD_SIZE

#endif


#define CIPHER_NUM          21

#define NONE                -1
#define TABLE               0
#define RC4                 1
#define RC4_MD5             2
#define AES_128_CFB         3
#define AES_192_CFB         4
#define AES_256_CFB         5
#define AES_128_CTR         6
#define AES_192_CTR         7
#define AES_256_CTR         8
#define BF_CFB              9
#define CAMELLIA_128_CFB    10
#define CAMELLIA_192_CFB    11
#define CAMELLIA_256_CFB    12
#define CAST5_CFB           13
#define DES_CFB             14
#define IDEA_CFB            15
#define RC2_CFB             16
#define SEED_CFB            17
#define SALSA20             18
#define CHACHA20            19
#define CHACHA20IETF        20


#define ONETIMEAUTH_FLAG 0x10
#define ADDRTYPE_MASK 0xEF

#define ONETIMEAUTH_BYTES 10U
#define CLEN_BYTES 2U
#define AUTH_BYTES (ONETIMEAUTH_BYTES + CLEN_BYTES)

typedef struct {
	cipher_evp_t *evp;
	uint8_t iv[MAX_IV_LENGTH];
} cipher_ctx_t;

typedef struct {
	cipher_kt_t *info;
	size_t iv_len;
	size_t key_len;
} cipher_t;


typedef struct buffer {
	size_t idx;
	size_t len;
	size_t capacity;
	char   *array;
} buffer_t;

typedef struct chunk {
	uint32_t idx;
	uint32_t len;
	uint32_t counter;
	buffer_t *buf;
} chunk_t;

typedef struct enc_ctx {
	uint8_t init;
	uint64_t counter;
	cipher_ctx_t evp;
} enc_ctx_t;

int ss_encrypt(buffer_t *plaintext, enc_ctx_t *ctx, size_t capacity);
int ss_decrypt(buffer_t *ciphertext, enc_ctx_t *ctx, size_t capacity);

void enc_ctx_init(int method,enc_ctx_t *ctx,int enc);
int enc_init(const char *pass,const char *method);
int enc_get_iv_len(void);
unsigned char *enc_md5(const unsigned char *d, size_t n, unsigned char *md);
void cipher_context_release(cipher_ctx_t *ctx);

int ss_onetimeauth(buffer_t *buf,uint8_t *iv,size_t capacity);
int ss_onetimeauth_verify(buffer_t *buf, uint8_t *iv);

int ss_check_hash(buffer_t *buf, chunk_t *chunk, enc_ctx_t *ctx, size_t capacity);
int ss_gen_hash(buffer_t *buf, uint32_t *counter, enc_ctx_t *ctx, size_t capacity);

int balloc(buffer_t *ptr, size_t capacity);
int brealloc(buffer_t *ptr, size_t len, size_t capacity);
void bfree(buffer_t *ptr);

#endif
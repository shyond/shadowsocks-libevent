#include "encrypt.h"
#include "utils.h"

#if defined(USE_CRYPTO_OPENSSL)
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#endif

//#define OFFSET_ROL(p, o) ((uint64_t)(*(p + o)) << (8 * o))

static uint8_t *enc_table;
static uint8_t *dec_table;
static uint8_t enc_key[MAX_KEY_LENGTH];//加密解密秘钥
static int enc_key_len;//key长度
static int enc_iv_len;//iv 长度
static int enc_method;//加密模式


//加密模式
static const char *supported_ciphers[CIPHER_NUM] = {
	"table",
	"rc4",
	"rc4-md5",
	"aes-128-cfb",
	"aes-192-cfb",
	"aes-256-cfb",
	"aes-128-ctr",
	"aes-192-ctr",
	"aes-256-ctr",
	"bf-cfb",
	"camellia-128-cfb",
	"camellia-192-cfb",
	"camellia-256-cfb",
	"cast5-cfb",
	"des-cfb",
	"idea-cfb",
	"rc2-cfb",
	"seed-cfb",
	"salsa20",
	"chacha20",
	"chacha20-ietf"
};

static const int supported_cipher_iv_size[CIPHER_NUM] = {
	0, 0, 16, 16, 16, 16, 16, 16, 16, 8, 16, 16, 16, 8, 8, 8, 8, 16, 8, 8, 12
};
static const int supported_cipher_key_size[CIPHER_NUM] = {
	0, 16, 16, 16, 24, 32, 16, 24, 32, 16, 16, 24, 32, 16, 8, 16, 16, 16, 32, 32, 32
};

int balloc(buffer_t *ptr, size_t capacity)
{
	memset(ptr, 0,sizeof(buffer_t));
	ptr->array    = ss_malloc(capacity);
	ptr->capacity = capacity;
	return capacity;
}

int brealloc(buffer_t *ptr, size_t len, size_t capacity)
{
	if (ptr == NULL)
		return -1;
	size_t real_capacity = max(len, capacity);
	if (ptr->capacity < real_capacity) {
		ptr->array    = ss_realloc(ptr->array, real_capacity);
		ptr->capacity = real_capacity;
	}
	return real_capacity;
}

void bfree(buffer_t *ptr)
{
	if(!ptr)
		return;
	ptr->idx = 0;
	ptr->len = 0;
	ptr->capacity = 0;
	if(ptr->array)
		ss_free(ptr->array);
}
static int safe_memcmp(const void *s1, const void *s2, size_t n)
{
	const unsigned char *_s1 = (const unsigned char *)s1;
	const unsigned char *_s2 = (const unsigned char *)s2;
	int ret                  = 0;
	size_t i;
	for (i = 0; i < n; i++)
		ret |= _s1[i] ^ _s2[i];
	return !!ret;
}

int enc_get_iv_len()
{
	return enc_iv_len;
}

unsigned char *enc_md5(const unsigned char *d, size_t n, unsigned char *md)
{
#if defined(USE_CRYPTO_OPENSSL)
	return MD5(d,n,md);
#endif
}

void table_init(const char *pass)
{

}

static int cipher_iv_size(const cipher_t* cipher)
{
#if defined(USE_CRYPTO_OPENSSL)
	if(cipher->info == NULL)
		return cipher->iv_len;
	else
		return EVP_CIPHER_iv_length(cipher->info);
#endif
}

static int cipher_key_size(const cipher_t* cipher)
{
#if defined(USE_CRYPTO_OPENSSL)
	if(cipher->info == NULL)
		return cipher->key_len;
	else
		return EVP_CIPHER_key_length(cipher->info);
#endif
}

//由原始password生成指定长度key MD5方式生成
static int bytes_to_key(const cipher_t *cipher, const digest_type_t *md,
	const uint8_t *pass, uint8_t *key)
{
	size_t datal;
	datal = strlen((const char *)pass);
#if defined(USE_CRYPTO_OPENSSL)
	MD5_CTX c;
	uint8_t md_buf[MAX_MD_SIZE];
	int nkey;
	int addmd;
	unsigned int i,j,mds;
	mds = 16;//16位md5
	nkey = cipher_key_size(cipher);//获取秘钥长度
	if(!pass)
		return nkey;

	memset(&c,0,sizeof(c));
	for(j = 0,addmd = 0; j<nkey;addmd++){
		MD5_Init(&c);//初始化
		if(addmd){
			MD5_Update(&c,md_buf,mds);//如果长度不够秘钥长度，用当前生成的md5作为原始数据再次生成md5
		}
		MD5_Update(&c,pass,datal);
		MD5_Final(md_buf,&c);

		//用生成md5赋值key，长度到达后停止赋值
		for(i = 0; i<mds;i++,j++){
			if(j >= nkey)
				break;
			key[j] = md_buf[i];
		}
	}

	return nkey;
#endif
}
static int rand_bytes(uint8_t *output, int len)
{
	int i = 0;
	for(i = 0; i < len ;i++){
		output[i] = abs(rand()%255);
	}

	return 0;
}

static const cipher_kt_t *get_cipher_type(int method)
{
	if (method <= TABLE || method >= CIPHER_NUM) {
		LOGE("get_cipher_type(): Illegal method");
		return NULL;
	}

	if (method == RC4_MD5) {
		method = RC4;
	}

	if (method >= SALSA20) {
		return NULL;
	}

	const char *ciphername = supported_ciphers[method];
#if defined(USE_CRYPTO_OPENSSL)
	return EVP_get_cipherbyname(ciphername);
#endif
}

static const digest_type_t *get_gidest_type(const char *digest)
{
	if (digest == NULL) {
		LOGE("get_digest_type(): Digest name is null");
		return NULL;
	}

#if defined(USE_CRYPTO_OPENSSL)
	return EVP_get_digestbyname(digest);
#endif
}

//初始化cipher
static void cipher_context_init(cipher_ctx_t *ctx, int method, int enc)
{
	if (method <= TABLE || method >= CIPHER_NUM) {
		LOGE("cipher_context_init(): Illegal method");
		return;
	}

	const char *ciphername = supported_ciphers[method];
	const cipher_kt_t *cipher = get_cipher_type(method);
#if defined(USE_CRYPTO_OPENSSL)
	ctx->evp = EVP_CIPHER_CTX_new();
	cipher_evp_t *evp = ctx->evp;

	if (cipher == NULL) {
		LOGE("Cipher %s not found in OpenSSL library", ciphername);
		FATAL("Cannot initialize cipher");
	}
	if (!EVP_CipherInit_ex(evp, cipher, NULL, NULL, NULL, enc)) {
		LOGE("Cannot initialize cipher %s", ciphername);
		exit(EXIT_FAILURE);
	}
	if (!EVP_CIPHER_CTX_set_key_length(evp, enc_key_len)) {
		EVP_CIPHER_CTX_cleanup(evp);
		LOGE("Invalid key length: %d", enc_key_len);
		exit(EXIT_FAILURE);
	}

	//设置填充字节
	if (method > RC4_MD5) {
		EVP_CIPHER_CTX_set_padding(evp, 1);
	}
#endif
}

//设置iv ，加密解密时调用
void cipher_context_set_iv(cipher_ctx_t *ctx, uint8_t *iv, size_t iv_len,int enc)
{
	const unsigned char *true_key;

	if (iv == NULL) {
		LOGE("cipher_context_set_iv(): IV is null");
		return;
	}

	//解密时iv是客户端传过来的，需要设置
	if (!enc) {
		memcpy(ctx->iv, iv, iv_len);
	}

	if (enc_method >= SALSA20) {
		return;
	}
	//RC4_MD5模式秘钥
	if (enc_method == RC4_MD5) {
		unsigned char key_iv[32];
		memcpy(key_iv, enc_key, 16);
		memcpy(key_iv + 16, iv, 16);
		true_key = enc_md5(key_iv, 32, NULL);
		iv_len   = 0;
	} else {
		true_key = enc_key;
	}
	cipher_evp_t *evp = ctx->evp;
	if (evp == NULL) {
		LOGE("cipher_context_set_iv(): Cipher context is null");
		return;
	}
#if defined(USE_CRYPTO_OPENSSL)
	if (!EVP_CipherInit_ex(evp, NULL, NULL, true_key, iv, enc)) {
		EVP_CIPHER_CTX_cleanup(evp);
		FATAL("Cannot set key and IV");
	}
#endif
}

void cipher_context_release(cipher_ctx_t *ctx)
{
	if (enc_method >= SALSA20) {
		return;
	}

#if defined(USE_CRYPTO_OPENSSL)
	EVP_CIPHER_CTX_free(ctx->evp);
#endif
}

//加密解密函数
static int cipher_context_update(cipher_ctx_t *ctx, uint8_t *output, size_t *olen,
	const uint8_t *input, size_t ilen)
{

	cipher_evp_t *evp = ctx->evp;
#if defined(USE_CRYPTO_OPENSSL)
	int err = 0, tlen = *olen;
	err = EVP_CipherUpdate(evp, (uint8_t *)output, &tlen,
		(const uint8_t *)input, ilen);
	*olen = tlen;
	return err;
#endif
}

 /*
         * Shadowsocks TCP Relay Header:
         *
         *    +------+----------+----------+----------------+
         *    | ATYP | DST.ADDR | DST.PORT |    HMAC-SHA1   |
         *    +------+----------+----------+----------------+
         *    |  1   | Variable |    2     |      10        |
         *    +------+----------+----------+----------------+
         *
         *    If ATYP & ONETIMEAUTH_FLAG(0x10) != 0, Authentication (HMAC-SHA1) is enabled.
         *
         *    The key of HMAC-SHA1 is (IV + KEY) and the input is the whole header.
         *    The output of HMAC-SHA is truncated to 10 bytes (leftmost bits).
         */

int ss_onetimeauth(buffer_t *buf,uint8_t *iv,size_t capacity)
{
	uint8_t hash[ONETIMEAUTH_BYTES*2];
	uint8_t auth_key[MAX_IV_LENGTH+MAX_KEY_LENGTH];
	//初始key = iv+key
	memcpy(auth_key,iv,enc_iv_len);
	memcpy(auth_key+enc_iv_len,enc_key,enc_key_len);
	brealloc(buf,ONETIMEAUTH_BYTES + buf->len,capacity);
#if defined(USE_CRYPTO_OPENSSL)
	HMAC(EVP_sha1(), auth_key, enc_iv_len + enc_key_len, (uint8_t *)buf->array, buf->len, (uint8_t *)hash, NULL);
#endif
	memcpy(buf->array + buf->len, hash, ONETIMEAUTH_BYTES);//拷贝10位hash
	buf->len += ONETIMEAUTH_BYTES;
}
int ss_onetimeauth_verify(buffer_t *buf, uint8_t *iv)
{
	uint8_t hash[ONETIMEAUTH_BYTES * 2];
	uint8_t auth_key[MAX_IV_LENGTH + MAX_KEY_LENGTH];
	memcpy(auth_key, iv, enc_iv_len);
	memcpy(auth_key + enc_iv_len, enc_key, enc_key_len);
	size_t len = buf->len - ONETIMEAUTH_BYTES;

#if defined(USE_CRYPTO_OPENSSL)
	HMAC(EVP_sha1(), auth_key, enc_iv_len + enc_key_len, (uint8_t *)buf->array, len, hash, NULL);

#endif

	return safe_memcmp(buf->array + len, hash, ONETIMEAUTH_BYTES);
}

int ss_encrypt(buffer_t *plain, enc_ctx_t *ctx, size_t capacity)
{
	// not table
	if(ctx){
		static buffer_t tmp = { 0, 0, 0, NULL };
		int err       = 1;
		size_t iv_len = 0;
		if (!ctx->init) {
			iv_len = enc_iv_len;
		}
		brealloc(&tmp, iv_len + plain->len, capacity);
		buffer_t *cipher = &tmp;
		cipher->len = plain->len;
		if (!ctx->init) {
			cipher_context_set_iv(&ctx->evp, ctx->evp.iv, iv_len, 1);//初始化cipher
			memcpy(cipher->array, ctx->evp.iv, iv_len);//首个包头部是IV
			ctx->counter = 0;//chunk ID初始化
			ctx->init    = 1;
		}
		if (enc_method >= SALSA20) {
			
			//暂不支持
			FATAL("not support!");

		} else {
			err =
				cipher_context_update(&ctx->evp,
				(uint8_t *)(cipher->array + iv_len),
				&cipher->len, (const uint8_t *)plain->array,
				plain->len);
			if (!err) {
				return -1;
			}
		}

		brealloc(plain, iv_len + cipher->len, capacity);
		memcpy(plain->array, cipher->array, iv_len + cipher->len);
		//第一次加密后的长度是IV+cipher,之后长度是cipher的长度
		plain->len = iv_len + cipher->len;//
	}else{//table 加密
		char *begin = plain->array;
		char *ptr   = plain->array;
		while (ptr < begin + plain->len) {
			*ptr = (char)enc_table[(uint8_t)*ptr];
			ptr++;
		}
		return 0;
	}
}

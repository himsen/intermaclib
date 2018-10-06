#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>
#include <ctype.h>
#include <openssl/evp.h>

/* Enables RDTSC measurement in measurements.h */
#define RDTSC

#include "measurements.h"

#define U32ENCODE(p, v) \
	do { \
		const u_int32_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 24) & 0xff; \
		((u_char *)(p))[1] = (__v >> 16) & 0xff; \
		((u_char *)(p))[2] = (__v >> 8) & 0xff; \
		((u_char *)(p))[3] = __v & 0xff; \
	} while (0)

#define U64ENCODE(p, v) \
	do { \
		const u_int64_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 56) & 0xff; \
		((u_char *)(p))[1] = (__v >> 48) & 0xff; \
		((u_char *)(p))[2] = (__v >> 40) & 0xff; \
		((u_char *)(p))[3] = (__v >> 32) & 0xff; \
		((u_char *)(p))[4] = (__v >> 24) & 0xff; \
		((u_char *)(p))[5] = (__v >> 16) & 0xff; \
		((u_char *)(p))[6] = (__v >> 8) & 0xff; \
		((u_char *)(p))[7] = __v & 0xff; \
	} while (0)

void dump_data(const void *s, size_t len, FILE *f) {

	size_t i, j;
	const u_char *p = (const u_char *)s;

	for (i = 0; i < len; i += 16) {
		fprintf(f, "%.4zu: ", i);
		for (j = i; j < i + 16; j++) {
			if (j < len)
				fprintf(f, "%02x ", p[j]);
			else
				fprintf(f, "   ");
		}
		fprintf(f, " ");
		for (j = i; j < i + 16; j++) {
			if (j < len) {
				if  (isascii(p[j]) && isprint(p[j]))
					fprintf(f, "%c", p[j]);
				else
					fprintf(f, ".");
			}
		}
		fprintf(f, "\n");
	}
}

int test_aes_gcm_clock(EVP_CIPHER_CTX *evp, u_char *src, u_int src_len,
	u_char *dst, u_char *nonce) {


	if (EVP_CipherInit_ex(evp, NULL, NULL, NULL, nonce, 1) == 0) {
		return 0;
	}

	if (EVP_Cipher(evp, dst, src, src_len) < 0) {
		return 0;
	}

	if (EVP_Cipher(evp, NULL, NULL, 0) < 0) {
		return 0;
	}

	return 1;
}

static inline int encode_nonce(u_char *nonce, uint32_t chunk_counter,
	uint64_t message_counter) {

	U32ENCODE(nonce, chunk_counter);
	U64ENCODE(nonce + 4, message_counter);

	return 1;
}

int main(int argc, char* argv[]) {

	EVP_CIPHER_CTX *evp = NULL;
	u_char nonce[16];
	u_char *key = NULL;
	u_char *dst = NULL;
	u_char *src = NULL;
	u_int src_len = 50 * 1024;
	u_int seed_pi = 314159;
	u_int key_len = 12;
	int i = 0;
	int j = 0;
	uint32_t chunk = 0;
	uint64_t msg = 0;
	int res = 0;

	srand(seed_pi);
		
	key = calloc(1, sizeof(u_char) * key_len);

	for (i = 0; i < key_len; ++i) {

		key[i] = rand();
		printf("%02X", key[i]);
	}
	printf("\n");

	src = calloc(1, sizeof(u_char) * src_len);

	for (i = 0; i < src_len; ++i) {
		src[i] = rand();
	}

	if ((evp = EVP_CIPHER_CTX_new()) == NULL) {
		goto out;
	}

	/* Pick cipher (EVP_aes_128_gcm) and set key */
	if (EVP_CipherInit(evp, EVP_aes_128_gcm(), key, NULL, 1) == 0) {
		goto out;
	}

	encode_nonce(nonce, chunk, msg);
	
	dst = calloc(1, sizeof(u_char) * src_len);

	MEASURE("ENCRYPT", test_aes_gcm_clock(evp, src, src_len, dst, nonce);, res);

	//dump_data(dst, src_len, stderr);

out:
	if (evp != NULL) {
		EVP_CIPHER_CTX_free(evp);
	}
	if (src != NULL) {
		free(src);
	}
	if (dst != NULL) {
		free(dst);
	}

	return 0;
}
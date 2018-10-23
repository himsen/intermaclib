#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>
#include <ctype.h>
#include <openssl/evp.h>

#define RDTSC

#include "im_measurements.h"

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

/* Similar to what is measured in libintermac */
int test_aes_gcm_clock(EVP_CIPHER_CTX *evp, u_char *src, u_int src_len,
	u_char *dst, u_char *nonce) {

	/* Set nonce */
	if (EVP_CipherInit(evp, NULL, NULL, nonce, 1) == 0) {
		return 0;
	}

	if (EVP_Cipher(evp, dst, src, src_len) < 0) {
		return 0;
	}

	if (EVP_Cipher(evp, NULL, NULL, 0) < 0) {
		return 0;
	}

	if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_GET_TAG, 16,
		dst + src_len) == 0) {
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
	u_int src_len = 8 * 1024;
	u_int seed_pi = 314159;
	u_int key_len = 12;
	int i = 0;
	uint32_t chunk = 0;
	uint64_t msg = 0;
	int res = 1;
	int count = 0;

	/* Seed random number generator */
	srand(seed_pi);

	/* Allocate key */
	key = calloc(1, sizeof(u_char) * key_len);

	/* Generate key */
	for (i = 0; i < key_len; ++i) {

		key[i] = rand();
		printf("%02X", key[i]);
	}
	printf("\n");

	/* Allocate src */
	src = calloc(1, sizeof(u_char) * src_len);

	/* Generate src */
	for (i = 0; i < src_len; ++i) {
		src[i] = rand();
	}

	/* Initialise EVP interface */
	if ((evp = EVP_CIPHER_CTX_new()) == NULL) {
		goto out;
	}

	/* Pick AES128-GCM, set key and set mode to encrypt */
	if (EVP_CipherInit(evp, EVP_aes_128_gcm(), key, NULL, 1) == 0) {
		goto out;
	}

	/* Encode nonce */
	encode_nonce(nonce, chunk, msg);

	/* Allocate dst */
	dst = calloc(1, sizeof(u_char) * (src_len + 16));

	/* Run benchmark */
	//for (i = 0; i < 50; ++i) {
		IM_MEASURE("ENCRYPT", res = test_aes_gcm_clock(evp, src, src_len, dst, nonce);, count);
 		//res = test_aes_gcm_clock(evp, src, src_len, dst, nonce);
		if (res == 0)
			fprintf(stderr, "ERROR\n");
	//}

	/* Dump data */
	//dump_data(src, src_len, stderr);
	//dump_data(dst, src_len, stderr);

out:
	/* Clean */
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

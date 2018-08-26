/*
 * Benchmark libInterMAC
 */

#include <stdio.h>
#include <string.h>
/*
#include <linux/preempt.h>
#include <linux/hardirq.h>
*/

#include "cpucycles.h"
#include "im_core.h"

#define IM_BENCH_WARM_UP 500
#define IM_BENCH_STAT_SIZE 5000
#define IM_BENCH_COMPLEXICTY_LOOP 1

#define _IM_BENCH_NUM_CIPHERS 2
char * im_bench_ciphers[] = {
	"im-aes128-gcm",
	"im-chacha-poly"
};
u_int im_bench_keylens[] = {
	128,
	256
};

#define IM_BENCH_NUM_CHUNKLENS 14
u_int im_bench_chunklens[] = {
	127,
	128,
	255,
	256,
	511,
	512,
	1023,
	1024,
	2047,
	2048,
	4095,
	4096,
	8191,
	8192
};

/*
 * Saves benchmarks
 */
void im_bench_save_result(u_int msg_size, char *function, char *cipher, u_int chunk_length,
	unsigned long long *clocks, int header) {

	FILE *fd = NULL;
	char *fname = NULL;
	char *prefix = "libim_bench_";
	int i = 0;

	/* Quick and dirty */
	fname = calloc(1, sizeof(char) * (strlen(prefix) + strlen(function) + strlen("_") + strlen(cipher) + 1));
	memcpy(fname, prefix, strlen(prefix));
	memcpy(fname + strlen(prefix), function, strlen(function));
	memcpy(fname + strlen(prefix) + strlen(function), "_", strlen("_"));
	memcpy(fname + strlen(prefix) + strlen(function) + strlen("_"), cipher, strlen(cipher) + 1);

	fd = fopen(fname, "a");

	if (fd != NULL) {

		if (header == 0) {
			fprintf(fd, "%s\n%s\n%u\n%d\n%d\n", function, cipher, msg_size,
				IM_BENCH_WARM_UP, IM_BENCH_STAT_SIZE);
		}
		else {
			fprintf(fd, "%u\n", chunk_length);
			for(i = 0; i < IM_BENCH_STAT_SIZE; ++i) {
				fprintf(fd, "%llu\n", clocks[i]);
			}
		}

		fclose(fd);
	}
}

/*
 * Test im_initialise()
 */
void im_bench_initialise(char *cipher, u_int chunk_length, char *key) {

	unsigned long flags;
	unsigned long long clocks[IM_BENCH_STAT_SIZE];
	unsigned long long clock_start = 0;
	unsigned long long clock_end = 0;
	int i = 0, j = 0;
	int res = 0;
	struct intermac_ctx *im_ctx = NULL;

	/* Warm up cache */
	for (i = 0; i < IM_BENCH_WARM_UP; ++i) {

		res = im_initialise(&im_ctx, key, chunk_length, cipher, 1);
		im_cleanup(im_ctx);
	}

	/* Take ownership of processor
	% Turns out this is not so easy to compile...
	preempt_disable();
	raw_local_irq_save(flags);
	*/

	/* Perform benchmark */
	for (j = 0; j < IM_BENCH_STAT_SIZE; ++j) {

		clock_start = cpucycles();

		res = im_initialise(&im_ctx, key, chunk_length, cipher, 1);

		clock_end = cpucycles();

		clocks[j] = clock_end - clock_start;

		im_cleanup(im_ctx);
	}

	/* Release ownership of processor
	% Turns out this is not so easy to compile
	raw_local_irq_rstore(flags);
	preempt_enable();
	*/

	/* Save benchmarks */
	im_bench_save_result(0, "initialise", cipher + 3, chunk_length, clocks, 1);
}

/*
 * Test im_encrypt()
 */
void im_bench_encrypt(char *cipher, u_int chunk_length, char *key,
	u_char *src, u_int src_length) {

	unsigned long long clocks[IM_BENCH_STAT_SIZE];
	unsigned long long clock_start = 0;
	unsigned long long clock_end = 0;
	int i = 0, j = 0;
	int res = 0;
	struct intermac_ctx *im_ctx = NULL;
	u_char *dst;
	u_int dst_length;

	/* Setup context */
	res = im_initialise(&im_ctx, key, chunk_length, cipher, 1);

	/* Warm up cache */
	for (i = 0; i < IM_BENCH_WARM_UP; ++i) {

		res = im_encrypt(im_ctx, &dst, &dst_length, src, src_length);
		free(dst);
		dst = NULL;
	}

	/* Perform benchmark */
	for (j = 0; j < IM_BENCH_STAT_SIZE; ++j) {

		clock_start = cpucycles();

		res = im_encrypt(im_ctx, &dst, &dst_length, src, src_length);

		clock_end = cpucycles();

		clocks[j] = clock_end - clock_start;

		free(dst);
		dst = NULL;
	}

	im_cleanup(im_ctx);

	/* Save benchmarks */
	im_bench_save_result(0, "encrypt", cipher + 3, chunk_length, clocks, 1);
}

/*
 * Test im_decrypt()
 */
void im_bench_decrypt(char *cipher, u_int chunk_length, char *key,
	u_char *src, u_int src_length) {

	unsigned long long clocks[IM_BENCH_STAT_SIZE];
	unsigned long long clock_start = 0;
	unsigned long long clock_end = 0;
	int i = 0, j = 0;
	int res = 0;
	struct intermac_ctx *im_ctx_encrypt = NULL;
	struct intermac_ctx *im_ctx_decrypt = NULL;
	u_char *dst;
	u_int dst_length;
	u_char *src_decrypted = NULL;
	u_int size_decrypted_ciphertext = 0;
	u_int total_allocated = 0;
	u_int this_processed = 0;

	/* Setup context for decrypt*/
	res = im_initialise(&im_ctx_decrypt, key, chunk_length, cipher, 0);
	/* Setup context for encrypt*/
	res = im_initialise(&im_ctx_encrypt, key, chunk_length, cipher, 1);

	/* Warm up cache */
	for (i = 0; i < IM_BENCH_WARM_UP; ++i) {

		res = im_encrypt(im_ctx_encrypt, &dst, &dst_length, src, src_length);

		res = im_decrypt(im_ctx_decrypt, dst, dst_length, &this_processed,
			&src_decrypted, &size_decrypted_ciphertext, &total_allocated);

		free(dst);
		dst = NULL;
	}

	/* Perform benchmark */
	for (j = 0; j < IM_BENCH_STAT_SIZE; ++j) {

		/* Encrypt once to have something to decrypt */
		res = im_encrypt(im_ctx_encrypt, &dst, &dst_length, src, src_length);

		clock_start = cpucycles();

		res = im_decrypt(im_ctx_decrypt, dst, dst_length, &this_processed,
			&src_decrypted, &size_decrypted_ciphertext, &total_allocated);

		clock_end = cpucycles();

		clocks[j] = clock_end - clock_start;

		free(dst);
		dst = NULL;
	}

	free(dst);
	im_cleanup(im_ctx_encrypt);
	im_cleanup(im_ctx_decrypt);

	/* Save benchmarks */
	im_bench_save_result(0, "decrypt", cipher + 3, chunk_length, clocks, 1);

}

void im_bench_run_init(u_char *keys[]) {

	int count_chunk_len = 0;
	int count_cipher = 0;

	/* Choose cipher */
	for (count_cipher = 0; count_cipher < _IM_BENCH_NUM_CIPHERS;
		++count_cipher){

		/* Put header */
		im_bench_save_result(0, "initialise", im_bench_ciphers[count_cipher] + 3,
			0, NULL, 0);

		/* Choose chunk length */
		for (count_chunk_len = 0; count_chunk_len < IM_BENCH_NUM_CHUNKLENS;
			++count_chunk_len) {

			im_bench_initialise(
				im_bench_ciphers[count_cipher],
				im_bench_chunklens[count_chunk_len],
				keys[count_cipher]
				);
		}
	}
}

void im_bench_run_enc(u_char *keys[], u_char *src, u_int src_length) {

	int count_chunk_len = 0;
	int count_cipher = 0;

	/* Choose cipher */
	for (count_cipher = 0; count_cipher < _IM_BENCH_NUM_CIPHERS;
		++count_cipher){

		/* Put header */
		im_bench_save_result(src_length, "encrypt", im_bench_ciphers[count_cipher] + 3,
			0, NULL, 0);

		/* Choose chunk length */
		for (count_chunk_len = 0; count_chunk_len < IM_BENCH_NUM_CHUNKLENS;
			++count_chunk_len) {

			im_bench_encrypt(
				im_bench_ciphers[count_cipher],
				im_bench_chunklens[count_chunk_len],
				keys[count_cipher],
				src,
				src_length
				);
		}
	}
}

void im_bench_run_dec(u_char *keys[], u_char *src, u_int src_length) {

	int count_chunk_len = 0;
	int count_cipher = 0;

	/* Choose cipher */
	for (count_cipher = 0; count_cipher < _IM_BENCH_NUM_CIPHERS;
		++count_cipher){

		/* Put header */
		im_bench_save_result(src_length, "decrypt", im_bench_ciphers[count_cipher] + 3,
			0, NULL, 0);

		/* Choose chunk length */
		for (count_chunk_len = 0; count_chunk_len < IM_BENCH_NUM_CHUNKLENS;
			++count_chunk_len) {

			im_bench_decrypt(
				im_bench_ciphers[count_cipher],
				im_bench_chunklens[count_chunk_len],
				keys[count_cipher],
				src,
				src_length
				);
		}
	}
}

int main(int argc, char *argv[]) {

	u_char *src = NULL;
	u_int src_length = 0;
	char *pattern = "abcdefgh";
	int i = 0;
	int div8 = 0;
	u_int key_chacha_poly_len = 32;
	u_int key_aes_gcm_len = 16;
	time_t seed;

	/* 
	 * Generate random key
	 * This is not supposed to be cryptographically random
	 */
	srand((unsigned) time(&seed));
	u_char *key_chacha_poly = calloc(1, sizeof(u_char)*key_chacha_poly_len);
	u_char *key_aes_gcm = calloc(1, sizeof(u_char)*key_aes_gcm_len);
	for (i = 0; i < key_chacha_poly_len; i++) {
		key_chacha_poly[i] = rand();
		printf("%02X", key_chacha_poly[i]);
	}
	printf("\n");
	for (i = 0; i < key_aes_gcm_len; i++) {
		key_aes_gcm[i] = rand();
		printf("%02X", key_aes_gcm[i]);
	}
	printf("\n");
	u_char * keys[2] = {key_aes_gcm, key_chacha_poly};

	/* Generate src data */
	src_length = 1024; /* 1kb */
	//src_length = 10 * 1024; /* 10kb */
	//src_length = 100 * 1024; /* 100kb */
	//src_length = 1024 * 1024; /* 1mb */
	src = malloc(sizeof(u_char) * src_length);
	div8 = src_length / 8; /* Read 8 bytes at a time */
	for(i = 0; i < div8; i = i + 8) {
		memcpy(src + i, pattern, 8);
	}

	/***** im_initialise() benchmark *****/

	im_bench_run_init(keys);

	/***** im_encrypt() benchmark *****/

	im_bench_run_enc(keys, src, src_length);

	/***** im_derypt() benchmark *****/

	im_bench_run_dec(keys, src, src_length);

	/* Free stuff */
	free(key_chacha_poly);
	free(key_aes_gcm);
	free(src);

	return 0;
}

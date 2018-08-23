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

#define IM_BENCH_WARM_UP 1
#define IM_BENCH_STAT_SIZE 1
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

#define IM_BENCH_NUM_CHUNKLENS 5
u_int im_bench_chunklens[] = {
	256,
	512,
	1024,
	2048,
	4096,
	8192
};

/*
 * Saves benchmarks
 */
void im_bench_save_result(char *function, char *cipher, u_int chunk_length,
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
			fprintf(fd, "%s\n%s\n%d\n%d\n", function, cipher,
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
 * Test im_init()
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
	im_bench_save_result("initialise", cipher + 3, chunk_length, clocks, 1);
}

/*
 * Test im_enc()
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
	im_bench_save_result("encrypt", cipher + 3, chunk_length, clocks, 1);
}

/*
 * Test im_dec()
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
	im_bench_save_result("decrypt", cipher + 3, chunk_length, clocks, 1);

}

int main(int argc, char *argv[]) {

	int count_chunk_len = 0;
	int count_cipher = 0;

	/* Generate random key */
	u_char *key_chacha_poly = calloc(1, sizeof(u_char)*32);
	u_char *key_aes_gcm = calloc(1, sizeof(u_char)*16);
	char * keys[2] = {key_aes_gcm, key_chacha_poly};

	/***** im_initialise() benchmark *****/

	/* Choose cipher */
	for (count_cipher = 0; count_cipher < _IM_BENCH_NUM_CIPHERS;
		++count_cipher){

		/* Put header */
		im_bench_save_result("initialise", im_bench_ciphers[count_cipher] + 3,
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

	/***** im_encrypt() benchmark *****/

	u_char *src = NULL;
	u_int src_length = 0;
	char *pattern = "abcdefgh";
	int i = 0;
	int div8 = 0;

	/* Generate src data */
	src_length = 100 * 1024; /* 100kb */
	src = malloc(sizeof(u_char) * src_length);
	div8 = src_length / 8; /* Read 8 bytes at a time */
	for(i = 0; i < div8; i = i + 8) {
		memcpy(src + i, pattern, 8);
	}

	/* Choose cipher */
	for (count_cipher = 0; count_cipher < _IM_BENCH_NUM_CIPHERS;
		++count_cipher){

		/* Put header */
		im_bench_save_result("encrypt", im_bench_ciphers[count_cipher] + 3,
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

	/***** im_derypt() benchmark *****/

	/* Choose cipher */
	for (count_cipher = 0; count_cipher < _IM_BENCH_NUM_CIPHERS;
		++count_cipher){

		/* Put header */
		im_bench_save_result("decrypt", im_bench_ciphers[count_cipher] + 3,
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

	free(key_chacha_poly);
	free(key_aes_gcm);
	free(src);

	return 0;
}

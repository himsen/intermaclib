/*
 * Benchmark libInterMAC
 *
 * This does not generally work on OSX, because RDTSC is not defined.
 */

#include <stdio.h>
#include <string.h>

#include "measurements.h"
#include "im_core.h"

#define SEED_PI 314159

#define IM_BENCH_STAT_SIZE 1000
#define IM_BENCH_WARM_UP IM_BENCH_STAT_SIZE/4
#define IM_BENCH_COMPLEXITY_LOOP 30
#define IM_BENCH_TOTAL_SAMPLE_SIZE IM_BENCH_WARM_UP + (IM_BENCH_STAT_SIZE * IM_BENCH_COMPLEXITY_LOOP)

#define IM_BENCH_NUM_SRC_LENGTS 4

#define _IM_BENCH_NUM_CIPHERS 2
char * im_bench_ciphers[] = {
	"im-aes128-gcm",
	"im-chacha-poly"
};
u_int im_bench_cipher_keylens[] = {
	16, /* im-aes128-gcm key length (counted in bytes) */
	32  /* im-chacha-poly key length (counted in bytes) */
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
void im_bench_save_result(time_t time, u_int msg_size, char *function, char *cipher, u_int chunk_length,
	double res, int header) {

	FILE *fd = NULL;
	char *fname = NULL;
	char *prefix = "libim_bench_";
	int i = 0;
	struct tm tm = *localtime(&time);

	/* Quick and dirty */
	fname = calloc(1, sizeof(char) * (strlen(prefix) + strlen(function) + strlen("_") + strlen(cipher) + 1));
	memcpy(fname, prefix, strlen(prefix));
	memcpy(fname + strlen(prefix), function, strlen(function));
	memcpy(fname + strlen(prefix) + strlen(function), "_", strlen("_"));
	memcpy(fname + strlen(prefix) + strlen(function) + strlen("_"), cipher, strlen(cipher) + 1);

	fd = fopen(fname, "a");

	if (fd != NULL) {

		if (header == 0) {
			fprintf(fd, "%d-%d-%d\n\n%s\n%s\n%u\n%d\n%d\n%d\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, function, cipher, msg_size,
				IM_BENCH_WARM_UP, IM_BENCH_COMPLEXITY_LOOP, IM_BENCH_STAT_SIZE);
		}
		else {
			fprintf(fd, "%u\n", chunk_length);
				fprintf(fd, "%0.2f\n", res);
		}

		fclose(fd);
	}
}

/*
 * Test im_initialise()
 */
void im_bench_initialise(char *cipher, u_int chunk_length, u_char *key) {

	int i = 0;
	double res = 0;
	struct intermac_ctx *im_ctx_list[IM_BENCH_TOTAL_SAMPLE_SIZE];

	/* Perform benchmark */
	MEASURE_NO_RESET("INITIALISE", im_initialise(im_ctx_list[RDTSC_MEASURE_ITERATOR], key, chunk_length, cipher, 1), res);

	/* Save benchmarks */
	im_bench_save_result(0, 0, "initialise", cipher + 3, chunk_length, res, 1);

	/* Clean up */
	for (i = 0; i < IM_BENCH_TOTAL_SAMPLE_SIZE; i++) {
		im_cleanup(im_ctx_list[i]);
	}
}

/*
 * Test im_encrypt()
 */
void im_bench_encrypt(char *cipher, u_int chunk_length, u_char *key,
	u_char *src, u_int src_length) {

/*
	unsigned long long clocks[IM_BENCH_STAT_SIZE];
	unsigned long long clock_start = 0;
	unsigned long long clock_end = 0;
	int i = 0, j = 0;
	int res = 0;
	struct intermac_ctx *im_ctx = NULL;
	u_char *dst;
	u_int dst_length;

	res = im_initialise(&im_ctx, key, chunk_length, cipher, 1);


	for (i = 0; i < IM_BENCH_WARM_UP; ++i) {

		res = im_encrypt(im_ctx, &dst, &dst_length, src, src_length);
		free(dst);
		dst = NULL;
	}


	for (j = 0; j < IM_BENCH_STAT_SIZE; ++j) {

		clock_start = cpucycles();

		res = im_encrypt(im_ctx, &dst, &dst_length, src, src_length);

		clock_end = cpucycles();

		clocks[j] = clock_end - clock_start;

		free(dst);
		dst = NULL;
	}

	im_cleanup(im_ctx);

	im_bench_save_result(0, "encrypt", cipher + 3, chunk_length, clocks, 1);
*/
}

/*
 * Test im_decrypt()
 */
void im_bench_decrypt(char *cipher, u_int chunk_length, u_char *key,
	u_char *src, u_int src_length) {
/*
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

	res = im_initialise(&im_ctx_decrypt, key, chunk_length, cipher, 0);

	res = im_initialise(&im_ctx_encrypt, key, chunk_length, cipher, 1);


	for (i = 0; i < IM_BENCH_WARM_UP; ++i) {

		res = im_encrypt(im_ctx_encrypt, &dst, &dst_length, src, src_length);

		res = im_decrypt(im_ctx_decrypt, dst, dst_length, &this_processed,
			&src_decrypted, &size_decrypted_ciphertext, &total_allocated);

		free(dst);
		dst = NULL;
	}

	for (j = 0; j < IM_BENCH_STAT_SIZE; ++j) {

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

	im_bench_save_result(0, "decrypt", cipher + 3, chunk_length, clocks, 1);

*/
}

void im_bench_run_init(time_t time, u_char *keys[]) {

	int count_chunk_len = 0;
	int count_cipher = 0;

	/* Choose cipher */
	for (count_cipher = 0; count_cipher < _IM_BENCH_NUM_CIPHERS;
		++count_cipher){

		/* Put header */
		im_bench_save_result(time, 0, "initialise", im_bench_ciphers[count_cipher] + 3,
			0, 0, 0);

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

void im_bench_run_enc(time_t time, u_char *keys[], u_char *src, u_int src_length) {

	int count_chunk_len = 0;
	int count_cipher = 0;

	/* Choose cipher */
	for (count_cipher = 0; count_cipher < _IM_BENCH_NUM_CIPHERS;
		++count_cipher){

		/* Put header */
		im_bench_save_result(time, src_length, "encrypt", im_bench_ciphers[count_cipher] + 3,
			0, 0, 0);

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

void im_bench_run_dec(time_t time, u_char *keys[], u_char *src, u_int src_length) {

	int count_chunk_len = 0;
	int count_cipher = 0;

	/* Choose cipher */
	for (count_cipher = 0; count_cipher < _IM_BENCH_NUM_CIPHERS;
		++count_cipher){

		/* Put header */
		im_bench_save_result(time, src_length, "decrypt", im_bench_ciphers[count_cipher] + 3,
			0, 0, 0);

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

	u_char *key_aes_gcm = NULL;
	u_char *key_chacha_poly = NULL;
	u_char *keys[_IM_BENCH_NUM_CIPHERS];
	u_char *src = NULL;
	u_char *srcs[IM_BENCH_NUM_SRC_LENGTS];
	u_char byte;
	unsigned int seed_pi = SEED_PI;
	int i = 0;
	int j = 0;
	int keylen = 0;
	int src_lengths[IM_BENCH_NUM_SRC_LENGTS];
	int src_length = 0;
	time_t time_header = time(NULL);

	/* Seed random number generator (not a cryptographic one) */
	srand(seed_pi);

	/* Generate keys */
	for (i = 0; i < _IM_BENCH_NUM_CIPHERS; i++) {
		
		keylen = im_bench_cipher_keylens[i];
		keys[i] = calloc(1, sizeof(u_char) * keylen);

		for (j = 0; j < keylen; j++) {

			keys[i][j] = rand();
			printf("%02X", key_aes_gcm[i]);
		}
		printf("\n");
	}

	/* Generate src data */
	src_lengths[0] = 1024; /* 1kb */
	src_lengths[1] = 8 * 1024; /* 8kb */
	src_lengths[2] = 15 * 1024; /* 15kb */
	src_lengths[3] = 50 * 1024; /* 50kb */

	srcs[0] = calloc(1, sizeof(u_char) * src_lengths[0]);
	srcs[1] = calloc(1, sizeof(u_char) * src_lengths[1]);
	srcs[2] = calloc(1, sizeof(u_char) * src_lengths[2]);
	srcs[3] = calloc(1, sizeof(u_char) * src_lengths[3]);

	for (i = 0; i < src_lengths[3]; i++) {

		byte = rand();

		if (i < src_lengths[0]) {
			srcs[0][i] = byte;
		}
		if (i < src_lengths[1]) {
			srcs[1][i] = byte;
		}
		if (i < src_lengths[2]) {
			srcs[2][i] = byte;
		}
		if (i < src_lengths[3]) {
			srcs[3][i] = byte;
		}
	}

	/***** im_initialise() benchmark *****/

	im_bench_run_init(time_header, keys);

	/***** im_encrypt() benchmark *****/

	//im_bench_run_enc(time_header, keys, srcs, src_lengths);

	/***** im_derypt() benchmark *****/

	//im_bench_run_dec(time_header, keys, srcs, src_lengths);

	/* Free stuff */
	for (i = 0; i < _IM_BENCH_NUM_CIPHERS; i++) {
		free(keys[i]);
	}
	for (i = 0; i < IM_BENCH_NUM_SRC_LENGTS; i++) {
		free(srcs[i]);
	}

	return 0;
}

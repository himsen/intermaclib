
#include <string.h>
#include <stdio.h>

#include "im_core.h"
#include "im_cipher.h"

#define im_div_roundup(x,y) ( 1 + ( ((x) - 1) / (y) ) ) /* Only works for x,y > 0 */


/* 
 * Computes the number of padding bytes needed to hit a multiple of 
 * the chunk length.
 * Because we want to avoid padding a whole chunk this number might be zero, which
 * must be specifically handled later.
 */
int im_padding_length_encrypt(u_int length, u_int chunk_length, u_int number_of_chunks, u_int *res) {

	u_int data_delimiters;
	u_int padding_length;

	data_delimiters = length + number_of_chunks; /* data + chunk delimiters */
	padding_length = chunk_length - (data_delimiters % chunk_length); /* How many bytes away chunk boundary */

	*res = padding_length % chunk_length; /* If we are on a boundary set padding to 0 */

	return IM_OK;
}

/*
 * (constant time) Compute length of padding. 
 * Compares consecutive bytes over the whole chunk to avoid leakage.  
 */
int im_padding_length_decrypt(u_char *decrypted_chunk, u_int chunk_length, u_int *padding_length) {

	u_int i;
	u_int padding_counter = 1;

	int flag = 0;

	/* If this is the case, there is something wrong! */
	if (chunk_length < 3) {
		return IM_ERR;
	}

	/* 
	 * decrypted_chunk[(chunk_length - 1) - *padding_length] = i'th char 
	 * decrypted_chunk[((chunk_length - 1) - 1) - *padding_length] = (i-1)'th char
	 * decrypted_chunk[chunk_length -1] is the chunk delimiter
	 */
	for (i = 0; i < chunk_length; i++) {
		flag |= memcmp(&decrypted_chunk[(chunk_length - 1) - padding_counter], &decrypted_chunk[((chunk_length - 1) - 1) - padding_counter], sizeof(u_char));

		if (!flag) {
			padding_counter = padding_counter + 1;
		}
	}

	/* If this is the case, there is something wrong! */
	if (padding_counter == chunk_length - 1) {
		return IM_ERR;
	}

	*padding_length = padding_counter;

	return 0;
}


/*
 * Adds aternating padding to a chunk
 * Padding byte depends on the last byte in 'src'
 */
int im_add_alternating_padding(u_char *src, u_char lastbyte, u_int padding_length, u_int chunk_length) {

	if (padding_length == 0) {
		return 0;
	}

	if (padding_length > chunk_length - 1) {
		return IM_ERR;
	}

	if (!memcmp(&lastbyte, "0", 1)) {
		if (!memset(src, '\x31', padding_length)) {
			return IM_ERR;
		}
	}
	else {
		if (!memset(src, '\x30', padding_length)) {
			return IM_ERR;
		}
	}

	return 0;
}

/*
 * Returns the length of the ciphertext when a string of length 'length'
 * is encrypted using intermac.
 */
int im_get_length(struct intermac_ctx *im_ctx, u_int length, u_int *res) {

	int noc; /* Number of chunks */

	/* div_roundup computation does not work for these specific values */
	if (length == 0 || im_ctx->chunk_length == 1) {
		return IM_ERR;
	}

	/* Computes number of chunks needed */
	noc = im_div_roundup(length, im_ctx->chunk_length - 1); 

	/* 
	 * Intermac ciphetext consists of 
	 * 'noc' encrypted chunks of length 'ciphertext_length' and 
	 * 'noc' MAC tags of length 'mactag_length'
	 */
	*res = (im_ctx->ciphertext_length * noc) + (im_ctx->mactag_length * noc);

	/* Save number of chunks */
	im_ctx->number_of_chunks = noc; 

	return 0;
}

/*
 * Encodes the nonce from 'chunk_counter' and 'message_counter'.
 * 'chunk_counter' treated as 32 bit and 'message_counter' is treated as 64 bit.
 * Nonce is encoded as
 * nonce = chunk_counter || message_counter in little endian form. 
 */
void im_encode_nonce(u_char *nonce, u_int chunk_counter, u_int message_counter) {

	IM_U32ENCODE(nonce, chunk_counter);
	IM_U64ENCODE(nonce + 4, message_counter);
}

/*
 * Allocates and initialises intermac context and cipher context.
 * Retrieves the chosen cipher.
 * Contexts must be freed using im_cleanup().
 */
int im_initialise(struct intermac_ctx **im_ctx, const u_char *enckey, u_int chunk_length, const char *cipher, int crypt_type) {

	int r; /* Error */

	u_char nonce[IM_NONCE_LENGTH];
	struct im_cipher_st_ctx _im_cs_ctx;

	/* Allocate contexts */
	*im_ctx = NULL;

	struct intermac_ctx *_im_ctx = NULL;
	if ((_im_ctx = calloc(1, sizeof(*_im_ctx))) == NULL) 
		return IM_ERR;
	struct im_cipher_ctx *_im_c_ctx = NULL;
	if ((_im_c_ctx = calloc(1, sizeof(*_im_c_ctx))) == NULL) 
		return IM_ERR;

	/* Retrieve the chosen cipher */
	const struct im_cipher * _cipher = im_get_cipher(cipher);

	/* Did the cipher exist? */
	if (_cipher == NULL) {
		return IM_ERR;
	}

	im_encode_nonce(nonce, 0, 0);

	/* Initialise cipher with key, nonce and encrypt/decrypt mode */
	if ((r = _cipher->init(&_im_cs_ctx, enckey, _cipher->key_len, nonce, crypt_type)) != 0) {
		return IM_ERR;
	}

	/* Set context constants and variables */
	_im_ctx->chunk_length = chunk_length;
	_im_ctx->ciphertext_length = chunk_length + _cipher->ciphertext_expansion;
	_im_ctx->mactag_length = _cipher->tag_len;
	_im_ctx->chunk_counter = 0;
	_im_ctx->message_counter = 0;
	_im_ctx->src_processed = 0;
	_im_ctx->number_of_chunks = 0;

	_im_ctx->decrypt_buffer_offset = 0;
	_im_ctx->decrypt_buffer_allocated = IM_DECRYPTION_BUFFER_LENGTH;

	_im_ctx->decryption_buffer = (u_char*) malloc(IM_DECRYPTION_BUFFER_LENGTH * sizeof(u_char));

	_im_c_ctx->cipher = _cipher;
	_im_c_ctx->im_cs_ctx = _im_cs_ctx;
	_im_ctx->im_c_ctx = _im_c_ctx;
	*(im_ctx) = _im_ctx;

	return 0;
}

/*
 * Intermac-encrypts 'src_length' bytes from 'src' and puts the result in 'dst'
 * Handles memory allocation for 'dst'
 * Caller must free 'dst'
 */
int im_encrypt(struct intermac_ctx *im_ctx, u_char **dst, u_int *dst_length, const u_char *src, u_int src_length) {

	u_int padding_length;
	u_int padding_offset;
	u_int k; /* Counter for processing the (k+1)th chunk of the unencoded message */
	u_int p; /* Offset to current plaintext */
	u_int pp; /* Offset to current destination for ciphertext */
	u_int number_of_chunks;
	u_int chunk_length = im_ctx->chunk_length;
	u_int ciphertext_length = im_ctx->ciphertext_length;
	u_int mactag_length = im_ctx->mactag_length;
	u_int chunk_counter = im_ctx->chunk_counter;
	u_int message_counter = im_ctx->message_counter;

	u_char chunkbuf[chunk_length];
	u_char chunk_delimiter_not_final = IM_CHUNK_DELIMITER_NOT_FINAL;
	u_char chunk_delimiter_final = IM_CHUNK_DELIMITER_FINAL;
	u_char chunk_delimiter_final_no_padding = IM_CHUNK_DELIMITER_FINAL_NO_PADDING;
	u_char nonce[IM_NONCE_LENGTH];

	/* Compute size (in bytes) of final ciphertext */
	if (im_get_length(im_ctx, src_length, dst_length) != 0) {
		return IM_ERR;
	}

	number_of_chunks = im_ctx->number_of_chunks;

	/* Allocate memory for final ciphertext */
	*dst = (u_char *) calloc(1, *dst_length);

	if (*dst == NULL) {
		return IM_ERR;
	}

	/* Compute size (in bytes) of padding */ 
	if (im_padding_length_encrypt(src_length, chunk_length, number_of_chunks, &padding_length) != IM_OK) {
		return IM_ERR;
	}

	/* Subtract 1 because of chunk delimiter */
	padding_offset = chunk_length - padding_length - 1; 

	/* 
	 * Loop that encrypts each chunk and computes MAC tag
	 * Put results in destination buffer 'dst'
	 */
	for (k = 0; k < number_of_chunks; k++) {

		p = k * (chunk_length - 1);
		pp = k * (ciphertext_length + mactag_length);

		// Add byte delimiter
		if ( k < number_of_chunks - 1 ) {

			memcpy(chunkbuf, src + p, chunk_length - 1);
			memcpy(chunkbuf + (chunk_length - 1), &chunk_delimiter_not_final, 1);
		}
		else {

			/* Add alternating padding */
			im_add_alternating_padding(chunkbuf + padding_offset, src[src_length - 1], padding_length, chunk_length);

			memcpy(chunkbuf, src + p, chunk_length - 1 - padding_length);

			if (padding_length) {
				memcpy(chunkbuf + (chunk_length - 1), &chunk_delimiter_final, 1); /* Padding needed */
			}
			else {
				memcpy(chunkbuf + (chunk_length - 1), &chunk_delimiter_final_no_padding, 1); /* Padding not needed */
			}
		}

		im_encode_nonce(nonce, chunk_counter, message_counter);
		
		/* Encrypts chunk and computes MAC tag using chosen cipher */
		if (im_ctx->im_c_ctx->cipher->do_cipher(&im_ctx->im_c_ctx->im_cs_ctx, nonce, *dst + pp, chunkbuf, chunk_length) != 0) {
			return IM_ERR;
		}

		chunk_counter = chunk_counter + 1;
	}

	im_ctx->message_counter = message_counter + 1;
	im_ctx->chunk_counter = 0;
	im_ctx->number_of_chunks = 0;

	return 0;
}

/*
 * To avoid leaking boundary, should do dummy decryptions if the entire ciphertext fragment is not decrypted. 
 */
int im_decrypt(struct intermac_ctx *im_ctx, const u_char *src, u_int src_length, u_int src_consumed, u_int *this_src_processed, u_char **dst, u_int *size_decrypted_packet, u_int *total_allocated) {

	u_char *decryption_buffer = im_ctx->decryption_buffer;
	u_char chunk_delimiter; /* Current chunk delimiter */
	u_char chunk_delimiter_final = IM_CHUNK_DELIMITER_FINAL;
	u_char chunk_delimiter_final_no_padding = IM_CHUNK_DELIMITER_FINAL_NO_PADDING;

	u_int chunk_length = im_ctx->chunk_length;
	u_int ciphertext_length = im_ctx->ciphertext_length;
	u_int mactag_length = im_ctx->mactag_length;
	u_int src_processed = im_ctx->src_processed; /* How much data processed from 'src' in previous calls */
	u_int padding_length = 0;
	u_int chunk_counter;
	u_int message_counter;
	u_int decrypt_buffer_offset;

	u_char decrypted_chunk[chunk_length];
	u_char expected_tag[mactag_length];
	u_char nonce[IM_NONCE_LENGTH];

	*size_decrypted_packet = 0;
	*this_src_processed = 0; /* How much data have been processed on 'this' call at any given time */

	for (;;) {

		chunk_counter = im_ctx->chunk_counter;
		message_counter = im_ctx->message_counter;
		decrypt_buffer_offset = im_ctx->decrypt_buffer_offset;

		if (decrypt_buffer_offset + (chunk_length - 1) > IM_DECRYPTION_BUFFER_LENGTH) {
			return IM_ERR;
		}

		if (src_length + src_consumed - src_processed - *this_src_processed < ciphertext_length + mactag_length) {
			return IM_OK; /* Wait for more bytes */
		}

		memcpy(expected_tag, src + (src_processed + *this_src_processed + ciphertext_length - src_consumed), mactag_length);

		im_encode_nonce(nonce, chunk_counter, message_counter);

		if (im_ctx->im_c_ctx->cipher->do_cipher(&im_ctx->im_c_ctx->im_cs_ctx, nonce, decrypted_chunk, src + (src_processed + *this_src_processed - src_consumed), chunk_length) != 0) {
			return IM_ERR;
		}

		memcpy(decryption_buffer + decrypt_buffer_offset, decrypted_chunk, chunk_length - 1);
		chunk_delimiter = decrypted_chunk[chunk_length - 1];

		im_ctx->decrypt_buffer_offset = decrypt_buffer_offset + (chunk_length - 1);
		im_ctx->chunk_counter = chunk_counter + 1;
		im_ctx->src_processed = im_ctx->src_processed + (ciphertext_length + mactag_length);
		*this_src_processed = *this_src_processed + (ciphertext_length + mactag_length);

		/* Check chunk delimiter; if chunk delimiter for final chunk, remove padding (if any) */
		if (!memcmp(&chunk_delimiter, &chunk_delimiter_final, 1)) {
			/* Final chunk processed but we have to remove some padding */
			if (im_padding_length_decrypt(decrypted_chunk, chunk_length, &padding_length) != 0) {
				return IM_ERR;
			}
			break;
		}
		else if (!memcmp(&chunk_delimiter, &chunk_delimiter_final_no_padding, 1)) {
			/* Final chunk processed but there is no padding */
			break;
		}
	}

	*dst = decryption_buffer;
	*size_decrypted_packet = im_ctx->decrypt_buffer_offset - padding_length;
	*total_allocated = im_ctx->decrypt_buffer_allocated;
	im_ctx->message_counter = message_counter + 1;
	im_ctx->decrypt_buffer_offset = 0;
	im_ctx->chunk_counter = 0;
	im_ctx->src_processed = 0;

	return 0;
}

/* 
 * Clean up.
 */
int im_cleanup(struct intermac_ctx *im_ctx) {

	if (im_ctx == NULL)
		return 0;

	/* Clean up internal cipher specifics */
	if (im_ctx->im_c_ctx->cipher->cleanup(&im_ctx->im_c_ctx->im_cs_ctx) != 0)
		return IM_ERR; 

	fprintf(stderr, "hi 1\n");

	/* Clean up cipher specifics */
	im_explicit_bzero(&im_ctx->im_c_ctx->im_cs_ctx, sizeof(im_ctx->im_c_ctx->im_cs_ctx));
	fprintf(stderr, "hi 2\n");
	im_explicit_bzero(im_ctx->im_c_ctx, sizeof(*im_ctx->im_c_ctx));
	fprintf(stderr, "hi 3\n");
	free(im_ctx->im_c_ctx);	
	im_ctx->im_c_ctx = NULL;
	fprintf(stderr, "hi 4\n");
	/* Clean up decryption buffer */
	im_explicit_bzero(im_ctx->decryption_buffer, IM_DECRYPTION_BUFFER_LENGTH * sizeof(u_char));
		fprintf(stderr, "hi 5\n");
	free(im_ctx->decryption_buffer);
	im_ctx->decryption_buffer = NULL;
	fprintf(stderr, "hi 6\n");
	/* Lastly, clean up the intermac context */
	im_explicit_bzero(im_ctx, sizeof(*im_ctx));
		fprintf(stderr, "hi 7\n");
	//free(im_ctx);
	im_ctx = NULL;
	fprintf(stderr, "hi 8\n");

	return 0;
}

/* TODO: remove */
void im_dump_data(const void *s, size_t len, FILE *f) {

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

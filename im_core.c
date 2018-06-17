/*
 * @file im_core.c
 * @brief Implements core InterMAC API: 
 * im_initialise()
 * im_encrypt()
 * im_decrypt()
 * im_cleanup()
 * 
 * @author Torben Hansen <Torben.Hansen.2015@rhul.ac.uk>
 */

#include <string.h>
#include <stdio.h>

#include "im_common.h"
#include "im_core.h"
#include "im_cipher.h"

/* Only works for x,y > 0 */
#define im_div_roundup(x,y) ( 1 + ( ((x) - 1) / (y) ) )

/* Internal im_core.c functions */
static inline int im_padding_length_encrypt(u_int length, u_int chunk_length, 
	u_int number_of_chunks, u_int *res);
static inline int im_get_length(struct intermac_ctx *im_ctx, u_int length,
	u_int *res);
static inline int im_add_alternating_padding(u_char *chunk, u_char last_byte,
	u_int padding_length, u_int chunk_length);
static inline void im_encode_nonce(u_char *nonce, u_int chunk_counter,
	u_int message_counter);
static int im_padding_length_decrypt(u_char *decrypted_chunk,
	u_int chunk_length, u_int *padding_length);

/* 
 * @brief Computes the number of padding bytes needed to hit a multiple of 
 * the chunk length.
 *
 * Because we want to avoid padding a whole chunk the
 * number of padding bytes can be zero.
 *
 * @param length The length of message encrypting
 * @param chunk_length The InterMAC chunk length parameter
 * @param number_of_chunks The number of chunks when _length_
 * bytes are InterMAC encoded
 * @param res Address to which the result is written
 * @return IM_OK on success, IM_ERR on failure
 */
static inline int im_padding_length_encrypt(u_int length, u_int chunk_length, 
	u_int number_of_chunks, u_int *res) {

	u_int data_encoded_len = 0;
	u_int padding_length = 0;

	/* Length of encoded data */
	data_encoded_len = length + number_of_chunks;

	/* Compute how many bytes away from chunk boundary */
	padding_length = chunk_length - (data_encoded_len % chunk_length);

	/* If we are on a boundary number of padding bytes is 0 */
	*res = padding_length % chunk_length; 

	return IM_OK;
}

/*
 * @brief Computes the length of padding, in a decrypted chunk, in constant
 * time.
 * @param decrypted_chunk The decrypted chunk 
 * @param chunk_length The InterMAC chunk length parameter
 * @param padding_length Address to which the result is written
 * @return IM_OK on success, IM_ERR on failure  
 */
static int im_padding_length_decrypt(u_char *decrypted_chunk,
	u_int chunk_length, u_int *padding_length) {

	u_int i = 0;
	u_int padding_counter = 1;
	int padding_end = 0;
	u_char padding_byte;

	/* If this is the case, there is something wrong! */
	if (chunk_length < 3) {
		return IM_ERR;
	}

	/* 
	 * Retrieve padding byte
	 * decrypted_chunk[chunk_length - 1] is the chunk delimiter
	 */
	padding_byte = decrypted_chunk[chunk_length - 2];

	/* 
	 * Run through decrypted chunk one byte at a time. Flag when a byte
	 * different from the padding byte is encountered.  
	 */
	for (i = 1; i < chunk_length - 1; i++) {

		padding_end |= memcmp(&padding_byte,
			&decrypted_chunk[(chunk_length - 2) - i], sizeof(u_char));

		if (padding_end == 0) {
			padding_counter = padding_counter + 1;
		}
	}

	*padding_length = padding_counter;

	return IM_OK;
}


/*
 * @brief Adds aternating padding to a chunk.
 * 
 * The padding byte used depends on the last byte in the parameter chunk:
 * If the last byte is '0' the padding byte is '1', otherwise the padding byte
 * is '0'.
 *
 * @param chunk The chunk on which padding is applied
 * @param last_byte The last byte of parameter chunk
 * @param padding_length Amount of padding that needs to be applied (counted in bytes)
 * @param chunk_length The InterMAC chunk_length parameter
 * @return IM_OK on success, IM_ERR on failure
 */
static inline int im_add_alternating_padding(u_char *chunk, u_char last_byte,
	u_int padding_length, u_int chunk_length) {

	if (padding_length == 0) {
		return IM_OK;
	}

	if (padding_length > chunk_length - 1) {
		return IM_ERR;
	}

	if (!memcmp(&last_byte, "0", 1)) {
		if (!memset(chunk, '\x31', padding_length)) {
			return IM_ERR;
		}
	}
	else {
		if (!memset(chunk, '\x30', padding_length)) {
			return IM_ERR;
		}
	}

	return IM_OK;
}

/*
 * @brief Computes the resulting length of the ciphertext of an InterMAC
 * encrytion of a plaintext.
 *
 * Also computes the resulting number of chunks of InterMAC encoding the 
 * plaintext. This number if saved in the InterMAC context. 
 *
 * @param im_ctx InterMAC context
 * @param length The length of plaintext
 * @param res Address to which the result is written
 * @return IM_OK on success, IM_ERR on failure
 */
static inline int im_get_length(struct intermac_ctx *im_ctx, u_int length,
	u_int *res) {

	int noc = 0;

	/* im_div_roundup computation cannot handle these specific values */
	if (length == 0 || im_ctx->chunk_length == 1) {
		return IM_ERR;
	}

	/* 
	 * Computes the number of chunks in an InterMAC encoding of a message
	 * of length _length_
	 */
	noc = im_div_roundup(length, im_ctx->chunk_length - 1); 

	/* 
	 * Intermac ciphetext consists of:
	 * _noc_ number of encrypted chunks of size ciphertext_length 
	 * (counted in bytes)
	 * _noc_ number of MAC tags of size mactag_length (counted in bytes)
	 */
	*res = (im_ctx->ciphertext_length * noc) + (im_ctx->mactag_length * noc);

	/* Save number of chunks for later */
	im_ctx->number_of_chunks = noc; 

	return IM_OK;
}

/*
 * @brief Encodes nonce
 *
 * The nonce is encoded as 
 * nonce = chunk_counter || message_counter
 * where both counters are treated as 32 bit strings.
 * 
 * @param nonce The address to which the result is written
 * @param chunk_counter The InterMAC chunk_counter
 * @param message_counter The InterMAC message_counter
 * @return Void
 */
static inline void im_encode_nonce(u_char *nonce, u_int chunk_counter,
	u_int message_counter) {

	IM_U32ENCODE(nonce, chunk_counter);
	IM_U64ENCODE(nonce + 4, message_counter);
}

/*
 * @brief Allocates and initialises intermac context and 
 * initialises internal InterMAC cipher.
 *
 * Caller must call im_cleaup to free _im_ctx_ and
 * im_cleanup() must be called if this function fails.
 *
 * @param im_ctx The addres to which the InterMAC context is written
 * @param key The symmetric key the internal cipher is initialised with
 * @param chunk_length The InterMAC chunk_length parameter
 * @param cipher The internal cipher InterMAC should use
 * @param crypt_type Initialises the internal InterMAC cipher
 * in either encrypt mode (IM_CIPHER_ENCRYPT)
 * or decrypt mode (IM_CIPHER_DECRYPT)
 * @return IM_OK on success, IM_ERR on failure
 */
int im_initialise(struct intermac_ctx **im_ctx, const u_char *key, 
	u_int chunk_length, const char *cipher, int crypt_type) {

	const struct im_cipher *chosen_cipher = NULL;
	struct im_cipher_ctx *_im_c_ctx = NULL;
	struct intermac_ctx *_im_ctx = NULL;
	struct im_cipher_st_ctx _im_cs_ctx;
	u_char nonce[IM_NONCE_LENGTH];
	int r = IM_OK;

	/* Retrieves the chosen cipher */
	if ((chosen_cipher = im_get_cipher(cipher)) == NULL) {
		return IM_ERR;
	}

	/* Allocate new contexts */
	if ((_im_ctx = (struct intermac_ctx *) calloc(1, sizeof(*_im_ctx)))
		== NULL) {
		r = IM_ERR;
		goto out;
	}
	if ((_im_c_ctx = (struct im_cipher_ctx *) calloc(1, sizeof(*_im_c_ctx)))
		== NULL) {
		r = IM_ERR;
		goto out;
	}

	/* 
	 * Encodes initial nonce with counters set to 0. 
	 * The nonce might not be used by the chosen cipher
	 */
	im_encode_nonce(nonce, 0, 0);

	/* 
	 * Initialises cipher with key, nonce and encrypt/decrypt mode
	 * The cipher context is written to _im_cs_ctx
	 */
	if ((r = chosen_cipher->init(&_im_cs_ctx, key, chosen_cipher->key_len,
		nonce, crypt_type)) != 0) {
		return IM_ERR;
	}

	/* The following sets the initial InterMAC state */
	_im_ctx->im_c_ctx = _im_c_ctx;
	_im_ctx->chunk_length = chunk_length;
	_im_ctx->ciphertext_length = chunk_length + chosen_cipher->ciphertext_expansion;
	_im_ctx->mactag_length = chosen_cipher->tag_len;
	_im_ctx->chunk_counter = 0;
	_im_ctx->message_counter = 0;
	_im_ctx->src_processed = 0;
	_im_ctx->number_of_chunks = 0;

	_im_ctx->decrypt_buffer_offset = 0;
	_im_ctx->decrypt_buffer_allocated = IM_DECRYPTION_BUFFER_LENGTH;
	_im_ctx->decryption_buffer = (u_char *) calloc(IM_DECRYPTION_BUFFER_LENGTH,
		sizeof(u_char));

	_im_c_ctx->cipher = chosen_cipher;
	_im_c_ctx->im_cs_ctx = _im_cs_ctx;
	*(im_ctx) = _im_ctx;

	/* The following memory is now owned by *im_ctx */
	_im_c_ctx = NULL;
	_im_ctx = NULL;

out:
	if (_im_c_ctx != NULL) {
		free(_im_c_ctx);
	}
	if (r != IM_OK ) {
		chosen_cipher->cleanup(&_im_cs_ctx);
	}
	if (_im_ctx != NULL) {
		free(_im_ctx);
	}
	return r;
}

/*
 * @brief InterMAC encrypts a message
 *
 * Caller must free _dst_. 
 *
 * @param im_ctx The InterMAC context
 * @param dst The address to which the encrypted message is written
 * @param dst_length The address to which the length of the 
 * encrypted message is written
 * @param src The message that is InterMAC encrypted
 * @param src_length The length of the message that is InterMAC encrypted
 * @return IM_OK on success, IM_ERR on failure
 */
int im_encrypt(struct intermac_ctx *im_ctx, u_char **dst, u_int *dst_length, 
	const u_char *src, u_int src_length) {

	u_int padding_length = 0;
	u_int padding_offset = 0;
	/* Counter for processing the (k+1)th chunk of the unencoded message */
	u_int k = 0;
	/* Offset to current chunk being processed */
	u_int current_chunk = 0; 
	/* Offset to current destination for ciphertext */
	u_int ciphertext_buffer_offset = 0;
	u_int number_of_chunks = 0;
	u_int chunk_length = im_ctx->chunk_length;
	u_int ciphertext_length = im_ctx->ciphertext_length;
	u_int mactag_length = im_ctx->mactag_length;
	u_int chunk_counter = im_ctx->chunk_counter;
	u_int message_counter = im_ctx->message_counter;

	u_char chunk_buf[chunk_length];
	u_char chunk_delimiter_not_final = IM_CHUNK_DELIMITER_NOT_FINAL;
	u_char chunk_delimiter_final = IM_CHUNK_DELIMITER_FINAL;
	u_char chunk_delimiter_final_no_padding = IM_CHUNK_DELIMITER_FINAL_NO_PADDING;
	u_char nonce[IM_NONCE_LENGTH];

	/* 
	 * Computes the size (in bytes) of final ciphertext 
	 * as well as the number of chunk (saved to im_ctx->number_of_chunks)
	 */
	if (im_get_length(im_ctx, src_length, dst_length) != 0) {
		return IM_ERR;
	}

	number_of_chunks = im_ctx->number_of_chunks;

	/* Allocates memory for final ciphertext */
	*dst = (u_char *) calloc(1, *dst_length);
	if (*dst == NULL) {
		return IM_ERR;
	}

	/* Computes the size (in bytes) of padding needed */ 
	if (im_padding_length_encrypt(src_length, chunk_length, number_of_chunks, 
		&padding_length) != IM_OK) {

		free(*dst);
		return IM_ERR;
	}

	/* Subtract 1 because of chunk delimiter */
	padding_offset = chunk_length - padding_length - 1; 

	/* 
	 * Loop that encrypts each chunk, computes MAC tag and append the MAC tag
	 * to the resulting chunk ciphertext.
	 * Writes results to address dst. 
	 */
	for (k = 0; k < number_of_chunks; k++) {

		current_chunk = k * (chunk_length - 1);
		ciphertext_buffer_offset = k * (ciphertext_length + mactag_length);

		/* Adds chunk delimiter */
		if ( k < number_of_chunks - 1 ) {
			/* No yet processing the final chunk */

			memcpy(chunk_buf, src + current_chunk, chunk_length - 1);
			memcpy(chunk_buf + (chunk_length - 1),
				&chunk_delimiter_not_final, 1);
		}
		else {
			/* We are now processing the final chunk */

			im_add_alternating_padding(chunk_buf + padding_offset, 
				src[src_length - 1], padding_length, chunk_length);

			memcpy(chunk_buf, src + current_chunk,
				chunk_length - 1 - padding_length);

			if (padding_length == 0) {
				/* Padding not needed */
				memcpy(chunk_buf + (chunk_length - 1),
					&chunk_delimiter_final_no_padding, 1);
			}
			else {
				/* Padding needed */
				memcpy(chunk_buf + (chunk_length - 1),
					&chunk_delimiter_final, 1);
			}
		}

		im_encode_nonce(nonce, chunk_counter, message_counter);
		
		/* 
		 * Encrypts chunk and computes MAC tag using chosen internal InterMAC
		 * cipher. Writes result to address dst + ciphertext_buffer_offset */
		if (im_ctx->im_c_ctx->cipher->do_cipher(&im_ctx->im_c_ctx->im_cs_ctx,
			nonce, *dst + ciphertext_buffer_offset, chunk_buf,
			chunk_length) != 0) {

			free(*dst);
			return IM_ERR;
		}

		chunk_counter = chunk_counter + 1;
	}

	im_ctx->message_counter = message_counter + 1;
	im_ctx->chunk_counter = 0;
	im_ctx->number_of_chunks = 0;

	return IM_OK;
}

/* TODO Make im_decrypt() signature easier to understand by removing src_consumed
 * It should really be an application responsibilityt o input the correct pointer
 * They would nede to store the src_consumed anyway, so should be able to increment 
 * the pointer correctly. We are safe because the verification will fail because 
 * chunk counter will be out-of-sync. In this line of thought we should also get 
 * red of src_processed which adds even more complexity.
 * In addition, think of ways to make this function easier to use, because atm 
 * it is highly complex which is not the intention of this library.
 */

/*
 * @brief InterMAC decrypts a ciphertext fragment. The function will
 * return when ONE ciphertext has been fully decrypted and will not 
 * attempt to decrypt further ciphertets (or ciphertext parts) that 
 * might be contained in a ciphertext fragment.
 *
 * The caller must NOT free the return pointer _*dst_. We are aware 
 * that this functions borders to insanity...
 *
 * @param im_ctc The InterMAC context
 * @param src The ciphertext fragment to be InterMAC decrypted
 * @param src_length The length of the ciphertext fragment to be InterMAC
 * decrypted
 * @param this_src_consumed The address to which the amount of bytes decrypted
 * of the ciphertext fragmentis written
 * @param dst The address to which the a decrypted ciphertext is written, note
 * that this will only happen when the full ciphertext has been decrypted
 * @param size_decrypted_ciphertext The address to which the size of the 
 * decrypted ciphertext is written
 * @param total_allocated The amout of memory (counted in bytes) allocated at 
 * the address dst
 * @return IM_OK && *dst == NULL if waiting for more data, IM_OK && *dst
 * != NULL if a ciphertext has been fully decrypted, IM_ERR on failure
 */
int im_decrypt(struct intermac_ctx *im_ctx, const u_char *src, u_int src_length, 
	u_int src_consumed, u_int *this_src_processed, u_char **dst, 
	u_int *size_decrypted_ciphertext, u_int *total_allocated) {

	/* TODO: This function could leak timing information becasue execution time atm
	 * depends on the length of the message being decrypted and not the length of 
	 * the ciphertext fragment. To counter this, a dummy decryption must be implemented
	 * the performs a fake decryption of the remaining ciphertext fragment (as long as
	 * there is enough data for a chunk ciphertext + mac tag) */

	u_char *decryption_buffer = im_ctx->decryption_buffer;
	u_char chunk_delimiter;/* Current chunk delimiter */
	u_char chunk_delimiter_not_final = IM_CHUNK_DELIMITER_NOT_FINAL;
	u_char chunk_delimiter_final = IM_CHUNK_DELIMITER_FINAL;
	u_char chunk_delimiter_final_no_padding = IM_CHUNK_DELIMITER_FINAL_NO_PADDING;

	u_int chunk_length = im_ctx->chunk_length;
	u_int ciphertext_length = im_ctx->ciphertext_length;
	u_int mactag_length = im_ctx->mactag_length;
	/*
	 * Saves how many ciphertect bytes hat has been
	 * processed in previous calls
	 */
	u_int src_processed = im_ctx->src_processed; 
	u_int padding_length = 0;
	u_int chunk_counter = 0;
	u_int message_counter = 0;
	u_int decrypt_buffer_offset = 0;

	int chunk_delimiter_final_no_padding_cmp = 0;
	int chunk_delimiter_final_cmp = 0;

	u_char decrypted_chunk[chunk_length];
	u_char expected_tag[mactag_length];
	u_char nonce[IM_NONCE_LENGTH];

	*size_decrypted_ciphertext = 0;
	/*
	 * Saves how many bytes that has been processed in *this* call at
	 * any given time
	 */
	*this_src_processed = 0; 

	for (;;) {

		/*
		 * Because this loop runs until a final chunk of a message has been
		 * decrypted or until we don't have an entire chunk, we must make sure
		 * to update the state
		 */
		chunk_counter = im_ctx->chunk_counter;
		message_counter = im_ctx->message_counter;
		decrypt_buffer_offset = im_ctx->decrypt_buffer_offset;

		/* Checks if the decryption buffer can store another chunk */
		if (decrypt_buffer_offset + (chunk_length - 1) > 
			IM_DECRYPTION_BUFFER_LENGTH) {
			return IM_ERR;
		}

		/* Checks if there are enough bytes to decrypt a chunk */
		if (src_length + src_consumed - src_processed - *this_src_processed < 
			ciphertext_length + mactag_length) {
			return IM_OK; /* Return IM_OK: wait for more bytes */
		}

		/* Extracts the MAC tag from chunk cipertext */
		memcpy(expected_tag, src + (src_processed + *this_src_processed + 
			ciphertext_length - src_consumed), mactag_length);

		im_encode_nonce(nonce, chunk_counter, message_counter);

		/* 
		 * Apply internal cipher on chunk.
		 * Returning from do_cipher implies that the chunk MAC has been verified
		 * and that the chunk has been decrypted.
		 * The decrypted chunk is written to the address decrypted_chunk.
		 */
		if (im_ctx->im_c_ctx->cipher->do_cipher(&im_ctx->im_c_ctx->im_cs_ctx, 
			nonce, decrypted_chunk,
			src + (src_processed + *this_src_processed - src_consumed),
			chunk_length) != 0) {
			return IM_ERR;
		}

		chunk_delimiter = decrypted_chunk[chunk_length - 1];

		chunk_delimiter_final_no_padding_cmp = memcmp(&chunk_delimiter, 
			&chunk_delimiter_final_no_padding, sizeof(u_char));
		chunk_delimiter_final_cmp = memcmp(&chunk_delimiter,
			&chunk_delimiter_final, sizeof(u_char));

		/* Checks whether we understand the final chunk delimiter */
		if (memcmp(&chunk_delimiter, &chunk_delimiter_not_final,
			sizeof(u_char)) != 0 && chunk_delimiter_final_no_padding_cmp !=0 &&
			chunk_delimiter_final_cmp != 0) {
			return IM_ERR;
		}

		/*
		 * Computes the padding length even though this might not be the 
		 * final chunk in a message or there might not be any padding. This
		 * serves as a precaution to not leaking timing information.
		 */
		if (im_padding_length_decrypt(decrypted_chunk, chunk_length,
			&padding_length) == IM_ERR) {
			return IM_ERR;
		}

		/* Copies the decrypted chunk to the decryption_buffer */
		memcpy(decryption_buffer + decrypt_buffer_offset, decrypted_chunk,
			chunk_length - 1);

		/*
		 * Updates decryption state variables to reflect we have decrypted
		 * another chunk
		 */
		im_ctx->decrypt_buffer_offset = decrypt_buffer_offset + (chunk_length - 1);
		im_ctx->chunk_counter = chunk_counter + 1;
		im_ctx->src_processed = im_ctx->src_processed + (ciphertext_length + mactag_length);
		*this_src_processed = *this_src_processed + (ciphertext_length + mactag_length);

		/* Checks if this chunk was the final chunk */
		if (chunk_delimiter_final_no_padding_cmp == 0) {
			/* Final chunk decrypted but there is no padding to be removed */
			padding_length = 0;
			break;
		}
		else if(chunk_delimiter_final_cmp == 0) {
			/* Final chunk decryoted but there is padding to be removed */
			break;
		}
	}

	/* 
	 * Message decrypted.
	 * Set result pointer to point to the message decrypted, 
	 * communicate its length, update counters and reset for next message.
	 */
	*dst = decryption_buffer;
	*size_decrypted_ciphertext = im_ctx->decrypt_buffer_offset - padding_length;
	*total_allocated = im_ctx->decrypt_buffer_allocated;
	im_ctx->message_counter = message_counter + 1;
	im_ctx->decrypt_buffer_offset = 0;
	im_ctx->chunk_counter = 0;
	im_ctx->src_processed = 0;

	return IM_OK;
}

/* 
 * @breif Clean ups InterMAC state internals
 * 
 * Cycles throughs the InterMAC context components and makes
 * sure to call appropriate clean up functions. In addition,
 * zeroises any data tied to the InterMAC state.
 *
 * @param im_ctx The InterMAC contect to clean up
 * @return IM_OK on success, IM_ERR on failure
 */
int im_cleanup(struct intermac_ctx *im_ctx) {

	if (im_ctx == NULL)
		return IM_ERR;

	/* Clean ups internal InterMAC cipher contect  */
	if (im_ctx->im_c_ctx != NULL) {

		/* Clean ups chosen cipher context */
		if (im_ctx->im_c_ctx->cipher != NULL) {
			im_ctx->im_c_ctx->cipher->cleanup(&im_ctx->im_c_ctx->im_cs_ctx);
		}

		/* Zeroises any chosen cipher internals */
		if (&im_ctx->im_c_ctx->im_cs_ctx != NULL) {
			im_explicit_bzero(&im_ctx->im_c_ctx->im_cs_ctx,
				sizeof(im_ctx->im_c_ctx->im_cs_ctx));
		}

		/* Zeroises and clean ups the InterMAC cipher context */
		im_explicit_bzero(im_ctx->im_c_ctx, sizeof(*im_ctx->im_c_ctx));
		free(im_ctx->im_c_ctx);	
		im_ctx->im_c_ctx = NULL;
	}

	/* Zeroises and clean ups decryption buffer */
	if (im_ctx->decryption_buffer != NULL) {
		im_explicit_bzero(im_ctx->decryption_buffer,
			IM_DECRYPTION_BUFFER_LENGTH * sizeof(u_char));
		free(im_ctx->decryption_buffer);
		im_ctx->decryption_buffer = NULL;		
	}

	/* Zeroises and clean ups the InterMAC context */
	im_explicit_bzero(im_ctx, sizeof(*im_ctx));
	free(im_ctx);
	im_ctx = NULL;

	return IM_OK;
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

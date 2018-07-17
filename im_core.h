/*
 * @file im_core.h
 *
 * @author Torben Hansen <Torben.Hansen.2015@rhul.ac.uk>
 */

#ifndef IM_CORE_H
#define IM_CORE_H

#include <sys/types.h>
#include <stdint.h>
#include <ctype.h>
#include <stdio.h>

#include "im_cipher.h"

/* Constants */

#define IM_DECRYPTION_BUFFER_LENGTH (256*1024)
#define IM_NONCE_LENGTH 12
#define IM_NONCE_CHUNK_CTR_BIT_LEN 4
#define IM_NONCE_CHUNK_CTR_LEN ((2^(IM_NONCE_CHUNK_CTR_BIT_LEN)) - 1)
#define IM_NONCE_MESSAGE_CTR_BIT_LEN 8
#define IM_NONCE_MESSAGE_CTR_LEN ((2^(IM_NONCE_MESSAGE_CTR_BIT_LEN)) - 1)
/* TODO below constants does not align with the InterMAC in practice paper */
#define IM_CHUNK_DELIMITER_NOT_FINAL '\x61'
#define IM_CHUNK_DELIMITER_FINAL '\x62'
#define IM_CHUNK_DELIMITER_FINAL_NO_PADDING '\x63'

/* Macro's */

#define IM_U32ENCODE(p, v) \
	do { \
		const u_int32_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 24) & 0xff; \
		((u_char *)(p))[1] = (__v >> 16) & 0xff; \
		((u_char *)(p))[2] = (__v >> 8) & 0xff; \
		((u_char *)(p))[3] = __v & 0xff; \
	} while (0)

#define IM_U64ENCODE(p, v) \
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

/* TODO should be opaque */
/* Intermac context definition */
struct intermac_ctx {
	/* Internal nonce-based cipher context */
	struct im_cipher_ctx *im_c_ctx;

	/* Includes chunk delimiter */
	u_int chunk_length;

	/* Incremented by one for each new chunk; reset for each new message */
	u_int chunk_counter;

	/* Incremented by one for each new message */
	u_int message_counter;

	/*
	 * Length of resulting ciphertext after encrypting 'chunk_length' bytes,
	 * for chosen encryption function (counted in bytes)
	 */
	u_int ciphertext_length;
	
	/* Length of MAC tag (counted in bytes) */
	u_int mactag_length;

	/* Number of chunks of current message being encrypted */
	u_int number_of_chunks; 

	/* Decryption specific */
	u_char *decryption_buffer; 
	u_int decrypt_buffer_offset;
	u_int decrypt_buffer_allocated;

	 /*
	  * Counts how many bytes that have been processed from input for current
	  * invocation of decryption function
	  */
	u_int src_processed;

	/*
	 * Encryption limit (counted in bytes).
	 * Zero means that no such limits exist.
	 * NOT implemented (TODO)
	 */
	uint32_t encryption_limit;

	/*
	 * Encryption invocation limit
	 * Zero means that no such limits exist.
	 * NOT implemented (TODO)
	 */
	uint32_t encryption_inv_limit;

	/*
	 * Authentication limit (counted in bytes).
	 * Zero means that no such limits exist.
	 * NOT implemented (TODO)
	 */
	uint32_t authentication_limit;

	/*
	 * Authentication invocation limit.
	 * Zero means that no such limits exist.
	 * NOT implemented (TODO)
	 */
	uint32_t authentication_inv_limit;

	/*
	 * Fail flag.
	 * If fail = 1 im_encrypt() and im_decrypt() will fail if 
	 * invoked.
	 */
	int fail;
};

/* Public InterMAC API */

int im_initialise(struct intermac_ctx**, const u_char*, u_int, const char*,
	int);
int im_encrypt(struct intermac_ctx*, u_char**, u_int*, const u_char*, u_int);
int im_decrypt(struct intermac_ctx*, const u_char*, u_int, u_int*,
	u_char**, u_int*, u_int*);
int im_cleanup(struct intermac_ctx*);

void im_dump_data(const void*, size_t, FILE*); /* TODO: remove */

#endif /* IM_CORE_H */

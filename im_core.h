#ifndef IM_CORE_H
#define IM_CORE_H

#include <sys/types.h>
#include <ctype.h>
#include <stdio.h>

#include "im_cipher.h"

/* Error codes */

#define IM_ERR	-1
#define IM_REKEY -2 /* TODO implement this */

/* Constants */

#define IM_NONCE_LENGTH 12
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

/* Intermac context definition */

struct intermac_ctx {
	struct imcipher_ctx *im_c_ctx;

	u_int chunk_length; /* Includes chunk delimiter */
	u_int chunk_counter; /* Incremented by one for each new chunk; reset for each new message */
	u_int message_counter; /* Incremented by one for each new message */
	u_int ciphertext_length; /*  Length of resulting ciphertext after encrypting 'chunk_length' bytes, for chosen encryption function (counted in bytes) */
	u_int mactag_length; /* Length of MAC tag (counted in bytes) */
	u_int number_of_chunks; /* Number of chunks of current message being encrypted(set in im_get_length) */ 
	u_int src_processed; /* Counts how many bytes have been processed from input for current invocation of decryption function */

	/* For supporting expandable buffer during decryption */
	u_int decrypt_buffer_size; 
	u_int decrypt_buffer_offset;
};

/* API */

int im_initialise(struct intermac_ctx**, const u_char*, u_int, const char*, int);
int im_get_length(struct intermac_ctx*, u_int, u_int*);
int im_encrypt(struct intermac_ctx*, u_char*, const u_char*, u_int);
int im_decrypt(struct intermac_ctx*, const u_char*, u_int, u_int, u_int*, u_char**, u_int*);
int im_cleanup(struct intermac_ctx*);

/* Internal functions */

int im_padding_length_encrypt(u_int, u_int, u_int, u_int*);
int im_add_alternating_padding(u_char*, u_char, u_int, u_int);
int im_padding_length_decrypt(u_char*, u_int, u_int*);
void im_encode_nonce(u_char*, u_int, u_int);

void dump_data(const void*, size_t, FILE*); /* TODO: remove */

#endif /* IM_CORE_H */

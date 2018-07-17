/*
 * @file im_cipher.c
 *
 * @author Torben Hansen <Torben.Hansen.2015@rhul.ac.uk>
 */

#include <stdio.h>
#include <string.h>

#include "im_cipher.h"

/* Cipher specific constants */
/* aes-gcm */
#define IM_AES_GCM_KEY_LENGTH 128
#define IM_AES_GCM_TAG_LENGTH 16
#define IM_AES_GCM_CT_EXPANSION 0
/* chacha20-poly1305 */
#define IM_CHACHA_POLY_KEY_LENGTH 256
#define IM_CHACHA_POLY_TAG_LENGTH 16
#define IM_CHACHA_POLY_CT_EXPANSION 0

/* Cipher specific limits */
/*
 * aes-gcm:
 * MAX chunk length < 2^{36} - 2^5
 * Actual MAX used 2^{32}
 */
#define IM_CIPHER_CHACHA_POLY_CHUNK_LENGTH 0xFFFFFFFF
/*
 * chacha20-poly1305:
 * MAX chunk length < 2^{70}
 * Actual MAX used 2^{32}
 */
#define IM_CIPHER_AES_GCM_CHUNK_LENGTH 0xFFFFFFFF


/* Register available internal InterMAC ciphers */
static const struct im_cipher ciphers[] = {
	{"im-aes128-gcm",
	IM_AES_GCM_KEY_LENGTH, IM_AES_GCM_TAG_LENGTH, IM_AES_GCM_CT_EXPANSION,
	im_aes_gcm_init, im_aes_gcm_cipher, im_aes_gcm_cleanup,
	IM_CIPHER_AES_GCM},
	{"im-chacha-poly",
	IM_CHACHA_POLY_KEY_LENGTH, IM_CHACHA_POLY_TAG_LENGTH,
	IM_CHACHA_POLY_CT_EXPANSION,
	im_chacha_poly_init, im_chacha_poly_cipher, im_chacha_poly_cleanup,
	IM_CIPHER_CHACHA_POLY}
};

/*
 * @brief Returns internal InterMAC cipher from name
 * @param name The name of the internal InterMAC cipher
 * @return Interal cipher or NULL if no cipher wiht _name_ exists
 */
const struct im_cipher * im_get_cipher(const char *name) {

	const struct im_cipher *c;

	for (c = ciphers; c->name != NULL; c++) {
		if (strcmp(c->name, name) == 0) {
			return c;
		}
	}
	
	return NULL;
}

/*
 * @brief Checks if requested cipher and requested chunk length are allowed
 * 
 * @param chunk_length The InterMAC chunk lenght parameter
 * @param cipher The internal cipher requested by user
 * @return 0 if chunk length and cipher combination is allowed, 1 if
 * combination is not allowed. Returns 0 if cipher is not recognised.
 */
int check_chunk_length_limit(u_int chunk_length,
	const struct im_cipher *cipher) {

	switch(cipher->flags) {
		case IM_CIPHER_CHACHA_POLY:
			if (chunk_length > IM_CIPHER_CHACHA_POLY_CHUNK_LENGTH) {
				return -1;
			}
			return 0;
		case IM_CIPHER_AES_GCM:
			if (chunk_length > IM_CIPHER_AES_GCM_CHUNK_LENGTH) {
				return -1;
			}
			return 0;
		default:
			return 0;
	}
}

/*
 * @brief Computes encryption limit (in bytes)
 * for a specific internal cipher for a specific chunk length
 *
 * NOT implemented (TODO)
 *
 * @param chunk_length The InterMAC chunk lenght parameter
 * @param cipher The internal cipher requested by user
 * @return Encryption limit (in bytes) or 0 if no limit
 */
uint32_t get_encryption_limit(u_int chunk_length,
	const struct im_cipher *cipher) {

	switch(cipher->flags) {
		case IM_CIPHER_CHACHA_POLY:
			return 0;
		case IM_CIPHER_AES_GCM:
			return 0;
		default:
			return 0;
	}
}

/*
 * @brief Computes the encryption invocation limit
 * for a specific internal cipher for a specific chunk length
 *
 * NOT implemented (TODO)
 *
 * @param chunk_length The InterMAC chunk lenght parameter
 * @param cipher The internal cipher requested by user
 * @return Encryption invocation limit (in bytes) or 0 if no limit
 */
uint32_t get_encryption_inv_limit(u_int chunk_length,
	const struct im_cipher *cipher) {

	switch(cipher->flags) {
		case IM_CIPHER_CHACHA_POLY:
			return 0;
		case IM_CIPHER_AES_GCM:
			return 0;
		default:
			return 0;
	}
}

/*
 * @brief Computes the authentication limit
 * for a specific internal cipher for a specific chunk length
 *
 * NOT implemented (TODO)
 *
 * @param chunk_length The InterMAC chunk lenght parameter
 * @param cipher The internal cipher requested by user
 * @return Authentication limit (in bytes) or 0 if no limit
 */
uint32_t get_authentication_limit(u_int chunk_length,
	const struct im_cipher *cipher) {

	switch(cipher->flags) {
		case IM_CIPHER_CHACHA_POLY:
			return 0;
		case IM_CIPHER_AES_GCM:
			return 0;
		default:
			return 0;
	}
}

/*
 * @brief Computes the authentication invocation limit
 * for a specific internal cipher for a specific chunk length
 *
 * NOT implemented (TODO)
 *
 * @param chunk_length The InterMAC chunk lenght parameter
 * @param cipher The internal cipher requested by user
 * @return Authentication invocation limit (in bytes) or 0 if no limit
 */
uint32_t get_authentication_inv_limit(u_int chunk_length,
	const struct im_cipher *cipher) {

	switch(cipher->flags) {
		case IM_CIPHER_CHACHA_POLY:
			return 0;
		case IM_CIPHER_AES_GCM:
			return 0;
		default:
			return 0;
	}
}

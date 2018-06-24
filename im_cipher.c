/*
 * @file im_cipher.c
 *
 * @author Torben Hansen <Torben.Hansen.2015@rhul.ac.uk>
 */

#include <stdio.h>
#include <string.h>

#include "im_cipher.h"

/* Cipher specific chunk length restrictions */
/* TODO update */
#define IM_CIPHER_CHACHA_POLY_CHUNK_LENGTH 10


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
 * @brief
 * 
 * @param
 * @param
 * @return
 */
int check_chunk_length_restrictions(u_int chunk_length,
	const struct im_cipher *cipher) {

	switch(cipher->flags) {
		case IM_CIPHER_CHACHA_POLY:
			if (chunk_length > IM_CIPHER_CHACHA_POLY_CHUNK_LENGTH) {
				return -1;
			}
			return 0;
		case IM_CIPHER_AES_GCM:
			return 0;
		default:
			return -1;
	}
}

/*
 * @brief
 * 
 * @param
 * @param
 * @return
 */
u_int get_encryption_limit(u_int chunk_length,
	const struct im_cipher *cipher) {

	return 0;
}

/*
 * @brief
 * 
 * @param
 * @param
 * @return
 */
u_int get_encryption_inv_limit(u_int chunk_length,
	const struct im_cipher *cipher) {

	return 0;
}

/*
 * @brief
 * 
 * @param
 * @param
 * @return
 */
u_int get_authentication_limit(u_int chunk_length,
	const struct im_cipher *cipher) {

	return 0;
}

/*
 * @brief
 * 
 * @param
 * @param
 * @return
 */
u_int get_authentication_inv_limit(u_int chunk_length,
	const struct im_cipher *cipher) {

	return 0;
}

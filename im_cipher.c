/*
 * @file im_cipher.c
 *
 * @author Torben Hansen <Torben.Hansen.2015@rhul.ac.uk>
 */

#include <stdio.h>
#include <string.h>

#include "im_cipher.h"

/* Definition available internal InterMAC ciphers */
static const struct im_cipher ciphers[] = {
	{"im-aes128-gcm", 128, 16, 0, im_aes_gcm_init, im_aes_gcm_cipher, im_aes_gcm_cleanup, IM_CIPHER_AES_GCM},
	{"im-chacha-poly", 256, 16, 0, im_chacha_poly_init, im_chacha_poly_cipher, im_chacha_poly_cleanup, IM_CIPHER_CHACHA_POLY}
};

/*
 * @brief Returns internal InterMAC cipher from name
 * @param name The name of the internal InterMAC cipher
 * @return Interal cipher or NULL if no cipher wiht _name_ exists
 */
const struct im_cipher * im_get_cipher(const char *name) {

	const struct im_cipher *c;

	for (c = ciphers; c->name != NULL; c++) {

		if (strcmp(c->name, name) == 0)
			return c;
	}
	
	return NULL;
}

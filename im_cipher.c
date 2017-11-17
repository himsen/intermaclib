
#include <stdio.h>
#include <string.h>

#include "im_cipher.h"

/* Available ciphers */
static const struct im_cipher ciphers[] = {
	{"im-aes128-gcm", 128, 16, 0, im_aes_gcm_init, im_aes_gcm_cipher, im_aes_gcm_cleanup, IM_CIPHER_AES_GCM},
	{"im-chacha-poly", 256, 16, 0, im_chacha_poly_init, im_chacha_poly_cipher, im_chacha_poly_cleanup, IM_CIPHER_CHACHA_POLY}
};

/* Returns a cipher */
const struct im_cipher * im_get_cipher(const char *name) {

	const struct im_cipher *c;

	for (c = ciphers; c->name != NULL; c++) {

		if (strcmp(c->name, name) == 0)
			return c;
	}
	
	return NULL;
}

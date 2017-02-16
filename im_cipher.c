
#include <stdio.h>

#include "im_cipher.h"

/* Available ciphers */
static const struct imcipher ciphers[] = {
	{"im-aes-gcm-128", 128, 16, 0, im_aes_gcm_init, im_aes_gcm_cipher, IMCIPHER_AES_GCM},
	{"im-chacha-poly", 256, 16, 0, im_chacha_poly_init, im_chacha_poly_cipher, IMCIPHER_CHACHA_POLY}
};

/* Returns a cipher */
const struct imcipher * im_get_cipher(const char *name) {

	const struct imcipher *c;

	for (c = ciphers; c->name != NULL; c++) {

		if (strcmp(c->name, name) == 0) {

			return c;
		}
	}
	
	return NULL;
}

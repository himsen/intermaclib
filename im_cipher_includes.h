#ifndef IM_CIPHER_INCLUDES_H
#define IM_CIPHER_INCLUDES_H

#define IM_CIPHER_ENCRYPT 1
#define IM_CIPHER_DECRYPT 0

/* im_chacha_poly_c includes */
#include "im_poly.h"
#include "im_chacha.h"

/* im_aes_gcm.c includes */
#include <openssl/evp.h>

/* Cipher states */
struct im_cipher_st_ctx {
 	/* crypt_type = 1 (encryption), crypt_type = 0 (decryption) */
	int crypt_type;

	/* im_chacha_poly.c context */
	struct im_chacha_ctx im_cc_ctx;

	/* im_aes_gcm.c context */
	EVP_CIPHER_CTX *evp;
};

void im_explicit_bzero(void*, size_t);
int im_timingsafe_bcmp(const void*, const void*, size_t);

#endif /* IM_CIPHER_INCLUDES_H */

/* 
 * Simple AES-GCM 128 bit cipher, which sets a new nonce for every call
 * Torben Hansen <Torben.Hansen.2015@rhul.ac.uk>
 */

#include "im_aes_gcm.h"

#include <stdio.h>

int im_aes_gcm_init(struct im_cipher_st_ctx *im_cs_ctx, const u_char *key, u_int key_len, u_char *nonce, int crypt_type) {


	if ((im_cs_ctx->evp = EVP_CIPHER_CTX_new()) == NULL) {

		return -1;
	}

	/* Pick cipher (EVP_aes_128_gcm) and set key */
	if (EVP_CipherInit(im_cs_ctx->evp, EVP_aes_128_gcm(), key, NULL, crypt_type) == 0) {

		return -1;
	}

	im_cs_ctx->crypt_type = crypt_type;

	return 0;
}

int im_aes_gcm_cipher(struct im_cipher_st_ctx *im_cs_ctx, u_char *nonce, u_char *dst, const u_char *src, u_int src_length) {

	int crypt_type = im_cs_ctx->crypt_type;

	if (crypt_type == IM_CIPHER_DECRYPT) {

		/* Sets the MAC tag */
		if(EVP_CIPHER_CTX_ctrl(im_cs_ctx->evp, EVP_CTRL_GCM_SET_TAG, 16, (u_char *) src + src_length) == 0) {
			return -1;
		}
	}

	/* Set new nonce */
	if (EVP_CipherInit(im_cs_ctx->evp, NULL, NULL, nonce, crypt_type) == 0) {
		return -1;
	}

	/* Encrypt/decrypt */
	if (EVP_Cipher(im_cs_ctx->evp, dst, src, src_length) < 0) {
		return -1;
	}

	/* Verify (on derypt) or compute (on encrypt) MAC tag */
	if (EVP_Cipher(im_cs_ctx->evp, NULL, NULL, 0) < 0) {
		return -1;
	}
	
	if (crypt_type == IM_CIPHER_ENCRYPT) {

		/* Set tag */
		if (EVP_CIPHER_CTX_ctrl(im_cs_ctx->evp, EVP_CTRL_GCM_GET_TAG, 16, dst + src_length) == 0) {
			return -1;
		}
	}

	return 0;
}

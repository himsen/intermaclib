/*
 * Copyright (c) 2013 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* TODO: Which license? */

#include <stddef.h>
#include <string.h>

#include "im_chacha_poly.h"

int im_chacha_poly_init(struct im_cipher_st_ctx *im_cs_ctx, const u_char *key, u_int key_len, u_char *nonce, int crypt_type) {

	if ((key_len / 8) != 32)
		return -1;

	im_chacha_keysetup(&im_cs_ctx->im_cc_ctx, key, 256);

	im_cs_ctx->crypt_type = crypt_type;

	return 0;
}

int im_chacha_poly_cipher(struct im_cipher_st_ctx *im_cs_ctx, u_char *nonce, u_char *dst, const u_char *src, u_int src_length) {

	int crypt_type = im_cs_ctx->crypt_type;
	const u_char one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 }; /* NB little-endian */
	u_char expected_tag[IM_POLY1305_TAGLEN], poly_key[IM_POLY1305_KEYLEN];
	
	if (nonce == NULL)
		return -1;

	memset(poly_key, 0, sizeof(poly_key));
	im_chacha_noncesetup(&im_cs_ctx->im_cc_ctx, nonce, NULL);
	im_chacha_encrypt_bytes(&im_cs_ctx->im_cc_ctx, poly_key, poly_key, sizeof(poly_key));

	if (crypt_type == IM_CIPHER_DECRYPT) {

		const u_char *tag = src + src_length;

		im_poly1305_auth(expected_tag, src, src_length, poly_key);
		if (im_timingsafe_bcmp(expected_tag, tag, IM_POLY1305_TAGLEN) != 0)
			return -1;
	}

	im_chacha_noncesetup(&im_cs_ctx->im_cc_ctx, nonce, one);
	im_chacha_encrypt_bytes(&im_cs_ctx->im_cc_ctx, src, dst, src_length);

	if (crypt_type == IM_CIPHER_ENCRYPT)
		im_poly1305_auth(dst + src_length, dst, src_length, poly_key);

	return 0;
}

int im_chacha_poly_cleanup(struct im_cipher_st_ctx *im_cs_ctx) {

	im_explicit_bzero(&im_cs_ctx->im_cc_ctx, sizeof(im_cs_ctx->im_cc_ctx));

	return 0;
}

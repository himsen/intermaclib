#ifndef IM_CIPHER_H
#define IM_CIPHER_H

#include <sys/types.h>

/* Available cipher implementations */
#include "im_aes_gcm.h"
#include "im_chacha_poly.h"

/* Intermac cipher definition */
struct im_cipher {
	char *name;
	u_int key_len;
	u_int tag_len;
	u_int ciphertext_expansion;
	int (*init)(struct im_cipher_st_ctx *ctx, const u_char *key, u_int key_len, u_char *nonce, int crypt_type);
	int (*do_cipher)(struct im_cipher_st_ctx *ctx, u_char *nonce, u_char *dst, const u_char *src, u_int src_length);
	void (*cleanup)(struct im_cipher_st_ctx *ctx);
	u_int flags;
#define IM_CIPHER_AES_GCM (1<<0)
#define IM_CIPHER_CHACHA_POLY (1<<1)
};

/* Intermac cipher context */
struct im_cipher_ctx {
	const struct im_cipher* cipher;
	struct im_cipher_st_ctx im_cs_ctx;
};

const struct im_cipher * im_get_cipher(const char *name);

#endif /* IM_CIPHER_H */

#ifndef IM_CHACHA_POLY_H
#define IM_CHACHA_POLY_H

#include <sys/types.h>
#include <ctype.h>
#include <stdio.h>
#include "cipher_includes.h"

/*
#include "im_chacha.h"

struct im_chacha_poly_ctx {
	struct chacha_ctx cc_ctx;
};
*/

int im_chacha_poly_init(struct im_cipher_st_ctx*, const u_char*, u_int, u_char*, int);

int im_chacha_poly_cipher(struct im_cipher_st_ctx*, u_char*, u_char*, const u_char*, u_int);

void dump_data(const void*, size_t, FILE*);

#endif /* IM_CHACHA_POLY_H */

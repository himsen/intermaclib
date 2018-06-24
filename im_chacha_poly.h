/*
 * @file im_chacha_poly.h
 *
 * @author Torben Hansen <Torben.Hansen.2015@rhul.ac.uk>
 */

#ifndef IM_CHACHA_POLY_H
#define IM_CHACHA_POLY_H

#include <sys/types.h>

#include "im_cipher_includes.h"

/* chacha20-poly1305 constants */
#define IM_CHACHA_POLY_KEY_LENGTH 128
#define IM_CHACHA_POLY_TAG_LENGTH 16
#define IM_CHACHA_POLY_CT_EXPANSION 0

int im_chacha_poly_init(struct im_cipher_st_ctx*, const u_char*, u_int, u_char*, int);
int im_chacha_poly_cipher(struct im_cipher_st_ctx*, u_char*, u_char*, const u_char*, u_int);
void im_chacha_poly_cleanup(struct im_cipher_st_ctx*);

#endif /* IM_CHACHA_POLY_H */

/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

/* TODO: which license? */

#ifndef IM_CHACHA_H
#define IM_CHACHA_H

#include <sys/types.h>
#include <stdlib.h>

struct im_chacha_ctx {
	u_int input[16];
};

#define IM_CHACHA_MINKEYLEN 	16
#define IM_CHACHA_NONCELEN		12
#define IM_CHACHA_CTRLEN		4
#define IM_CHACHA_STATELEN		(IM_CHACHA_NONCELEN+IM_CHACHA_CTRLEN)
#define IM_CHACHA_BLOCKLEN		64

void im_chacha_keysetup(struct im_chacha_ctx*, const u_char*, u_int)
    __attribute__((__bounded__(__minbytes__, 2, IM_CHACHA_MINKEYLEN)));
void im_chacha_noncesetup(struct im_chacha_ctx*, u_char*, const u_char*)
    __attribute__((__bounded__(__minbytes__, 2, IM_CHACHA_NONCELEN)))
    __attribute__((__bounded__(__minbytes__, 3, IM_CHACHA_CTRLEN)));
void im_chacha_encrypt_bytes(struct im_chacha_ctx*, const u_char*,
    u_char*, u_int)
    __attribute__((__bounded__(__buffer__, 2, 4)))
    __attribute__((__bounded__(__buffer__, 3, 4)));

#endif	/* IM_CHACHA_H */
/* 
 * Public Domain poly1305 from Andrew Moon
 * poly1305-donna-unrolled.c from https://github.com/floodyberry/poly1305-donna
 */

/* TODO: which license? */

#ifndef IM_POLY1305_H
#define IM_POLY1305_H

#include <sys/types.h>

#define IM_POLY1305_KEYLEN		32
#define IM_POLY1305_TAGLEN		16

void im_poly1305_auth(u_char*, const u_char*, size_t,
    const u_char*)
    __attribute__((__bounded__(__minbytes__, 1, IM_POLY1305_TAGLEN)))
    __attribute__((__bounded__(__buffer__, 2, 3)))
    __attribute__((__bounded__(__minbytes__, 4, IM_POLY1305_KEYLEN)));


#endif	/* IM_POLY1305_H */

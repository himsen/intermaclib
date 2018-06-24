/*
 * @file im_aes_gcm.h
 *
 * @author Torben Hansen <Torben.Hansen.2015@rhul.ac.uk>
 */

#ifndef IM_AES_GCM_H
#define IM_AES_GCM_H

#include "im_cipher_includes.h"

/* aes-gcm constants */
#define IM_AES_GCM_KEY_LENGTH 128
#define IM_AES_GCM_TAG_LENGTH 16
#define IM_AES_GCM_CT_EXPANSION 0

int im_aes_gcm_init(struct im_cipher_st_ctx*, const u_char*, u_int, u_char*, int);
int im_aes_gcm_cipher(struct im_cipher_st_ctx*, u_char*, u_char*, const u_char*, u_int);
void im_aes_gcm_cleanup(struct im_cipher_st_ctx*);

#endif /* IM_AES_GCM_H */

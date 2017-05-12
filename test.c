/* Unit tests */

#include "im_core.h"
#include <stdio.h>

int main(void) {
	
	printf("Intermac tests start\n");

	printf("\nChaCha20-Poly1305 encrypt/decrypt ----------------\n\n");

	struct intermac_ctx *im_encrypt_ctx = NULL;

	u_char* enckey = (u_char*) "11111111111111111111111111111111";

	if (im_initialise(&im_encrypt_ctx, enckey, 128, "im-chacha-poly", IM_CIPHER_ENCRYPT) != 0) {
		return 0;
	}

	const u_char* src = (const u_char*) "abcdefghijklmno";
	u_int src_length = 15;
	u_int dst_length = 0;

	u_char *dst;

	printf("Encrypting:\n");
	im_dump_data(src, src_length, stderr);

	if (im_encrypt(im_encrypt_ctx, &dst, &dst_length, src, src_length) != 0) {
		return 0;
	}

	im_cleanup(im_encrypt_ctx);

	struct intermac_ctx *im_decrypt_ctx = NULL;

	if (im_initialise(&im_decrypt_ctx, enckey, 128, "im-chacha-poly", IM_CIPHER_DECRYPT) != 0) {
		return 0;
	}

	u_char *decrypted_packet;
	u_int this_src_processed = 0;
	u_int length_decrypted_packet = 0;
	u_int total_allocated = 0;

	if (im_decrypt(im_decrypt_ctx, dst, dst_length, 0, &this_src_processed, &decrypted_packet, &length_decrypted_packet, &total_allocated) != 0) {
		return 0;		
	}

	printf("Decrypted:\n");
	im_dump_data(decrypted_packet, length_decrypted_packet, stderr);
	
	im_cleanup(im_decrypt_ctx);

	printf("Intermac tests done\n");

	return 0;
}
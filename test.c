//Tester

#include "im_core.h"
#include <stdio.h>
//#include "intermac-integration.h"
//#include "cipher.h"

int main(void) {
	
	printf("HEJ START\n");

	struct intermac_ctx *im_encrypt_ctx = NULL;

	//im_encrypt_ctx = calloc(sizeof(*im_encrypt_ctx), 1);

	u_char* enckey = (u_char*) "1111111111111111";

	//u_char* iv = (u_char*) "111111111111";

	if (im_initialise(&im_encrypt_ctx, enckey, 128, "im-chacha-poly", 1) != 0) {
		return 0;
	}

	const u_char* src = (const u_char*) "abcdefghijklmno";
	u_int src_length = 15;
	u_int dst_length = 0;
/*
	printf("im_encrypt_ctx chunk length: %i\n", im_encrypt_ctx->chunk_length);
	printf("im_encrypt_ctx decrypt_buffer_realloc: %i\n", im_encrypt_ctx->decrypt_buffer_realloc);
	printf("im_encrypt_ctx ciphetext length: %i\n", im_encrypt_ctx->ciphertext_length);
	printf("im_encrypt_ctx decrypt_buffer_offset: %i\n", im_encrypt_ctx->decrypt_buffer_offset);
	printf("im_encrypt_ctx decrypt_buffer_size: %i\n", im_encrypt_ctx->decrypt_buffer_size);
	printf("im_encrypt_ctx chunk_counter: %i\n", im_encrypt_ctx->chunk_counter);
	printf("im_encrypt_ctx chunk_message: %i\n", im_encrypt_ctx->message_counter);	
	printf("im_encrypt_ctx cipher tag_len: %i\n", im_encrypt_ctx->im_c_ctx->cipher->tag_len);
	printf("im_encrypt_ctx cipher state crypt_type: %i\n", im_encrypt_ctx->im_c_ctx->im_cs_ctx.crypt_type);
*/

	im_get_length(im_encrypt_ctx, src_length, &dst_length);

	u_char dst[dst_length];

	printf("Encrypting:\n");
	dump_data(src, src_length, stderr);

	if (im_encrypt(im_encrypt_ctx, dst, src, src_length) != 0) {
		return 0;
	}

	if (im_cleanup(im_encrypt_ctx) != 0) {
		return 0;
	}


	struct intermac_ctx *im_decrypt_ctx = NULL;

	if (im_initialise(&im_decrypt_ctx, enckey, 128, "im-chacha-poly", 0) != 0) {
		return 0;
	}

/*
	printf("im_decrypt_ctx chunk length: %i\n", im_decrypt_ctx->chunk_length);
	printf("im_decrypt_ctx decrypt_buffer_realloc: %i\n", im_decrypt_ctx->decrypt_buffer_realloc);
	printf("im_decrypt_ctx ciphetext length: %i\n", im_decrypt_ctx->ciphertext_length);
	printf("im_decrypt_ctx decrypt_buffer_offset: %i\n", im_decrypt_ctx->decrypt_buffer_offset);
	printf("im_decrypt_ctx decrypt_buffer_size: %i\n", im_decrypt_ctx->decrypt_buffer_size);
	printf("im_decrypt_ctx chunk_counter: %i\n", im_decrypt_ctx->chunk_counter);
	printf("im_decrypt_ctx chunk_message: %i\n", im_decrypt_ctx->message_counter);	
	printf("im_decrypt_ctx cipher tag_len: %i\n", im_decrypt_ctx->im_c_ctx->cipher->tag_len);
	printf("im_decrypt_ctx cipher state crypt_type: %i\n", im_decrypt_ctx->im_c_ctx->im_cs_ctx.crypt_type);
*/

	u_char *decrypted_packet;
	u_int length_decrypted_packet = 0;

	if (im_decrypt(im_decrypt_ctx, dst, dst_length, 0, &decrypted_packet, &length_decrypted_packet) != 0) {
		return 0;		
	}

	printf("Decrypted:\n");
	dump_data(decrypted_packet, length_decrypted_packet, stderr);

	printf("HEJ DONE\n");

	return 0;
}
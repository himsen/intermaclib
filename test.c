//Tester

#include "im_core.h"
#include <stdio.h>
//#include "intermac-integration.h"
//#include "cipher.h"

int main(void) {
	
	printf("Intermac tests start\n");

	printf("\nChaCha20-Poly1305 encrypt/decrypt ----------------\n\n");

	struct intermac_ctx *im_encrypt_ctx = NULL;

	//im_encrypt_ctx = calloc(sizeof(*im_encrypt_ctx), 1);

	u_char* enckey = (u_char*) "1111111111111111";

	//u_char* iv = (u_char*) "111111111111";

	if (im_initialise(&im_encrypt_ctx, enckey, 128, "im-chacha-poly", IM_CIPHER_ENCRYPT) != 0) {
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
	im_dump_data(src, src_length, stderr);

	if (im_encrypt(im_encrypt_ctx, dst, src, src_length) != 0) {
		return 0;
	}

	const u_char* src2 = (const u_char*) malloc(sizeof(u_char) * 512);
	memset(src2, 49, sizeof(u_char) * 512);

	u_int src_length2 = 512;
	u_int dst_length2 = 0;

	im_get_length(im_encrypt_ctx, src_length2, &dst_length2);

	u_char dst2[dst_length2];

	printf("Encrypting:\n");
	im_dump_data(src2, src_length2, stderr);

	if (im_encrypt(im_encrypt_ctx, dst2, src2, src_length2) != 0) {
		return 0;
	}

	const u_char* src3 = (const u_char*) malloc(sizeof(u_char) * 600);
	memset(src3, 49, sizeof(u_char) * 600);

	u_int src_length3 = 600;
	u_int dst_length3 = 0;

	im_get_length(im_encrypt_ctx, src_length3, &dst_length3);

	u_char dst3[dst_length3];

	printf("Encrypting:\n");
	im_dump_data(src3, src_length3, stderr);

	if (im_encrypt(im_encrypt_ctx, dst3, src3, src_length3) != 0) {
		return 0;
	}

	const u_char* src4 = (const u_char*) malloc(sizeof(u_char) * 368);
	memset(src4, 49, sizeof(u_char) * 368);

	u_int src_length4 = 368;
	u_int dst_length4 = 0;

	im_get_length(im_encrypt_ctx, src_length4, &dst_length4);

	u_char dst4[dst_length4];

	printf("Encrypting:\n");
	im_dump_data(src4, src_length4, stderr);


	if (im_encrypt(im_encrypt_ctx, dst4, src4, src_length4) != 0) {
		return 0;
	}

	if (im_cleanup(im_encrypt_ctx) != 0) {
		return 0;
	}


	struct intermac_ctx *im_decrypt_ctx = NULL;

	if (im_initialise(&im_decrypt_ctx, enckey, 128, "im-chacha-poly", IM_CIPHER_DECRYPT) != 0) {
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
	u_int this_processed = 0;
	u_int length_decrypted_packet = 0;

	if (im_decrypt(im_decrypt_ctx, dst, dst_length, 0, &this_processed, &decrypted_packet, &length_decrypted_packet) != 0) {
		return 0;		
	}

	printf("Decrypted 1:\n");
	im_dump_data(decrypted_packet, length_decrypted_packet, stderr);

	u_char *decrypted_packet2;
	u_int this_processed2 = 0;
	u_int length_decrypted_packet2 = 0;

	if (im_decrypt(im_decrypt_ctx, dst2, dst_length2, 0, &this_processed2, &decrypted_packet2, &length_decrypted_packet2) != 0) {
		return 0;		
	}

	printf("Decrypted 2:\n");
	im_dump_data(decrypted_packet2, length_decrypted_packet2, stderr);

	u_char *decrypted_packet3;
	u_int this_processed3 = 0;
	u_int length_decrypted_packet3 = 0;

	if (im_decrypt(im_decrypt_ctx, dst3, dst_length3, 0, &this_processed3, &decrypted_packet3, &length_decrypted_packet3) != 0) {
		return 0;		
	}

	printf("Decrypted 3:\n");
	im_dump_data(decrypted_packet3, length_decrypted_packet3, stderr);

	u_char *decrypted_packet4;
	u_int this_processed4 = 0;
	u_int length_decrypted_packet4 = 0;

	if (im_decrypt(im_decrypt_ctx, dst4, 200, 0, &this_processed4, &decrypted_packet4, &length_decrypted_packet4) != 0) {
		return 0;		
	}

	if (im_decrypt(im_decrypt_ctx, dst4, dst_length4, 0, &this_processed4, &decrypted_packet4, &length_decrypted_packet4) != 0) {
		return 0;		
	}

	printf("Decrypted 4:\n");
	im_dump_data(decrypted_packet4, length_decrypted_packet4, stderr);


	if (im_cleanup(im_decrypt_ctx) != 0) {
		return 0;
	}

	free(decrypted_packet);
	free(decrypted_packet2);
	free(decrypted_packet3);
	free(decrypted_packet4);


	printf("\nAES-GCM-128 encrypt/decrypt ----------------\n\n");

	struct intermac_ctx *im_encrypt_aes_gcm_ctx = NULL;

	//im_encrypt_ctx = calloc(sizeof(*im_encrypt_ctx), 1);

	u_char* enckey_aes_gcm = (u_char*) "1111111111111111";

	//u_char* iv = (u_char*) "111111111111";

	if (im_initialise(&im_encrypt_aes_gcm_ctx, enckey_aes_gcm, 128, "im-aes128-gcm", IM_CIPHER_ENCRYPT) != 0) {
		return 0;
	}

	const u_char* _src = (const u_char*) "abcdefghijklmno";
	u_int _src_length = 15;
	u_int _dst_length = 0;
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

	im_get_length(im_encrypt_aes_gcm_ctx, _src_length, &_dst_length);

	u_char _dst[_dst_length];

	printf("Encrypting:\n");
	im_dump_data(_src, _src_length, stderr);

	if (im_encrypt(im_encrypt_aes_gcm_ctx, _dst, _src, _src_length) != 0) {
		printf("fails encrypt\n");
		return 0;
	}

	const u_char* _src2 = (const u_char*) malloc(sizeof(u_char) * 368);
	memset(_src2, 49, sizeof(u_char) * 368);

	u_int _src_length2= 368;
	u_int _dst_length2 = 0;

	im_get_length(im_encrypt_aes_gcm_ctx, _src_length2, &_dst_length2);

	u_char _dst2[_dst_length2];

	printf("Encrypting:\n");
	im_dump_data(_src2, _src_length2, stderr);


	if (im_encrypt(im_encrypt_aes_gcm_ctx, _dst2, _src2, _src_length2) != 0) {
		printf("Fail fail\n");
		return 0;
	}

	if (im_cleanup(im_encrypt_aes_gcm_ctx) != 0) {
		return 0;
	}



	struct intermac_ctx *im_decrypt_aes_gcm_ctx = NULL;

	if (im_initialise(&im_decrypt_aes_gcm_ctx, enckey_aes_gcm, 128, "im-aes128-gcm", IM_CIPHER_DECRYPT) != 0) {
		return 0;
	}

	u_char *_decrypted_packet;
	u_int _this_processed = 0;
	u_int _length_decrypted_packet = 0;

	if (im_decrypt(im_decrypt_aes_gcm_ctx, _dst, _dst_length, 0, &_this_processed, &_decrypted_packet, &_length_decrypted_packet) != 0) {
		printf("Fails decrypt\n");	
		return 0;		
	}

	printf("Decrypted (aes-gcm) 1:\n");
	im_dump_data(_decrypted_packet, _length_decrypted_packet, stderr);


	u_char *_decrypted_packet2;
	u_int _this_processed2 = 0;
	u_int _length_decrypted_packet2 = 0;

	if (im_decrypt(im_decrypt_aes_gcm_ctx, _dst2, 200, 0, &_this_processed2, &_decrypted_packet2, &_length_decrypted_packet2) != 0) {
		return 0;		
	}

	if (im_decrypt(im_decrypt_aes_gcm_ctx, _dst2, _dst_length2, 0, &_this_processed2, &_decrypted_packet2, &_length_decrypted_packet2) != 0) {
		return 0;		
	}

	printf("Decrypted 4:\n");
	im_dump_data(_decrypted_packet2, _length_decrypted_packet2, stderr);


	printf("Intermac tests done\n");

	return 0;
}
printf "Compiling aes test benchmark\n"
gcc -o test_aes test_aes.c -lcrypto
printf "Run aes test benchmark: ./test_aes\n"
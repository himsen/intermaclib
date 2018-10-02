printf "Compiling benchmarks\n"
gcc -I../ -c im_bench_new.c
gcc im_bench_new.o -o im_bench_new -L.. -lintermac -lcrypto
printf "Run benchmarks: ./im_bench_new\n"

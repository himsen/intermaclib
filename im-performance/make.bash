printf "Compiling dependency\n"
cd cpucycles-20060326
printf  "Dependency test run\n"
sh do
cd ..
printf "Compiling benchmarks\n"
gcc -I../ -Icpucycles-20060326 -c im_bench.c
gcc cpucycles-20060326/cpucycles.o im_bench.o -o im_bench -L.. -lintermac -lcrypto
printf "Run benchmarks: ./im_bench\n"

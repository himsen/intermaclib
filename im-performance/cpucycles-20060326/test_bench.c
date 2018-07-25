/* Testing benchmark */

#include "cpucycles.h"
#include <stdio.h>

int main(int argc, char *argv[]) {
	
	unsigned long long c_start = 0;
	unsigned long long c_finish = 0;
	int inc = 0;
	int i = 0;

	c_start = cpucycles();

	for (; i < 10; i++)
		inc = inc + i;

	c_finish = cpucycles();

	fprintf(stderr, "CPU cycles: %llu\n", c_finish - c_start);

	return 0;
}
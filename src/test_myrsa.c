/**
 * test_myrsa.c - Unit tests for myrsa functions.
 */

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include "myrsa.h"

void test_generate_RSA_keys()
{
	uint64_t prime1, prime2;
	uint64_t n, e, d;

	generate_RSA_keys(prime1 = 11, prime2 = 17, &n, &e, &d);
	assert(e == 19);
	assert(d == 59);
	assert(n == 187);
}

void test_RSA_trapdoor()
{
	uint64_t message, key, modulus;
	assert(RSA_trapdoor(message = 5, key = 3, modulus = 11) == 4);
	assert(RSA_trapdoor(987654321, 123456789, 1000000007) == 379110096);
}

int main()
{
	test_generate_RSA_keys();
	test_RSA_trapdoor();

	/* Add calls to more test functions as needed... */

	return EXIT_SUCCESS;
}

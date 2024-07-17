/**
 * test_myrsa.c - Unit tests for myrsa functions.
 *
 * Author: Benjamin Chin.
 */

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include "myrsa.h"

void test_generate_RSA_keys()
{
	uint32_t prime1, prime2;
	uint32_t n, e, d;

	generate_RSA_keys(prime1 = 11, prime2 = 17, &n, &e, &d);
	assert(e == 3);
	assert(d == 107);
	assert(n == 187);
}

void test_RSA_trapdoor()
{
	uint32_t message, key, modulus;
	assert(RSA_trapdoor(message = 5, key = 3, modulus = 11) == 4);
	assert(RSA_trapdoor(987654321, 123456789, 1000000007) == 379110096);
}

void test_crc()
{
	assert(crc16_ccitt("", 0) == 0xFFFF);
	assert(crc16_ccitt("a", 1) == 0x9D77);
	assert(crc16_ccitt("The quick brown fox jumps over the lazy dog", 43) ==
	       0x8FDD);

	assert(crc16_ccitt_table_lookup("", 0) == 0xFFFF);
	assert(crc16_ccitt_table_lookup("a", 1) == 0x9D77);
	assert(crc16_ccitt_table_lookup(
		       "The quick brown fox jumps over the lazy dog", 43) ==
	       0x8FDD);
}

int main()
{
	test_generate_RSA_keys();
	test_RSA_trapdoor();
	test_crc();

	/* Add calls to more test functions as needed... */

	return EXIT_SUCCESS;
}

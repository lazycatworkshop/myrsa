/* test_myrsa.c - Unit tests for myrsa.c */

/* assert() is required */
#if defined(NDEBUG)
#define RESTORE_ASSERT
#undef NDEBUG
#endif

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "myrsa.h"
#include "big_number.h"

static void test_generate_RSA_keys()
{
	uint64_t prime1, prime2;
	uint64_t n, e, d;

	generate_RSA_keys(prime1 = 11, prime2 = 17, &n, &e, &d);
	assert(e == 19);
	assert(d == 59);
	assert(n == 187);
}

static void test_RSA_trapdoor()
{
	uint64_t message, key, modulus;
	assert(RSA_trapdoor(message = 5, key = 3, modulus = 11) == 4);
	assert(RSA_trapdoor(987654321, 123456789, 1000000007) == 379110096);
}

/* Test RSA_trapdoor_big */
static void test_RSA_trapdoor_big()
{
	bn message = bn_from_int(5);
	bn key = bn_from_int(3);
	bn modulus = bn_from_int(11);
	bn result = RSA_trapdoor_big(message, key, modulus);
	assert(result.size == 1);
	assert(result.data[0] == 4);

	message = bn_from_int(987654321);
	key = bn_from_int(123456789);
	modulus = bn_from_int(1000000007);
	result = RSA_trapdoor_big(message, key, modulus);
	assert(result.size == 4);
	assert(result.data[0] == 0x16);
	assert(result.data[1] == 0x98);
	assert(result.data[2] == 0xc2);
	assert(result.data[3] == 0xd0);

	/* Add more test cases... */
}

int main()
{
	test_generate_RSA_keys();
	test_RSA_trapdoor();
	test_RSA_trapdoor_big();

	/* Add calls to more test functions as needed... */

	return EXIT_SUCCESS;
}

#if defined(RESTORE_ASSERT)
#undef RESTORE_ASSERT
#define NDEBUG
#endif

/**
 * test_myrsa.c - Unit tests for myrsa functions.
 *
 * Author: Benjamin Chin.
 */

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include "myrsa.h"

/* Prototype of the function to be tested */
void generate_RSA_keys(uint32_t p, uint32_t q, uint32_t *n, uint32_t *e,
		       uint32_t *d);

/* Struct to hold test cases */
typedef struct {
	uint32_t prime1;
	uint32_t prime2;
	uint32_t expected_n;
	uint32_t expected_e;
	uint32_t expected_d;
} rsa_key_test_case;

void run_test_case(rsa_key_test_case test)
{
	uint32_t n, e, d;
	generate_RSA_keys(test.prime1, test.prime2, &n, &e, &d);
	assert(e == test.expected_e);
	assert(d == test.expected_d);
	assert(n == test.expected_n);
}

void test_generate_RSA_keys()
{
	rsa_key_test_case tests[] = {
		{ .prime1 = 11,
		  .prime2 = 17,
		  .expected_n = 187,
		  .expected_e = 3,
		  .expected_d = 107 },
		/*
		 * Add more test cases here...
		 * Example:
		 * { .prime1 = 13, .prime2 = 19, .expected_n = 247, .expected_e = 5, .expected_d = 77 },
		 */
	};

	size_t num_tests = sizeof(tests) / sizeof(tests[0]);
	for (size_t i = 0; i < num_tests; ++i) {
		run_test_case(tests[i]);
	}
}

int main()
{
	test_generate_RSA_keys();

	/* Add calls to more test functions as needed... */

	return EXIT_SUCCESS;
}
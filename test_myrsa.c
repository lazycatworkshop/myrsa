/**
 * test_myrsa.c - Unit tests for myrsa functions.
 *
 * Author: Benjamin Chin.
 */

#include <assert.h>
#include <stdlib.h>
#include "myrsa.h"

int main()
{
	/* Test generate_RSA_keys function */
	{
#define PRIME1 11
#define PRIME2 17
#define EXPECTED_KEY1 3
#define EXPECTED_KEY2 107
#define EXPECTED_MODULUS 187

		int n;
		int e;
		int d;
		generate_RSA_keys(PRIME1, PRIME2, &n, &e, &d);
		assert((e == EXPECTED_KEY1) && (d == EXPECTED_KEY2) &&
		       (n == EXPECTED_MODULUS));
	}

	/* Add more tests as needed... */

	return EXIT_SUCCESS;
}
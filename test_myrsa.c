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

		int key1[2];
		int key2[2];
		generate_RSA_keys(PRIME1, PRIME2, key1, key2);
		assert((key1[0] == EXPECTED_KEY1) &&
		       (key1[1] == EXPECTED_MODULUS) &&
		       (key2[0] == EXPECTED_KEY2) &&
		       (key2[1] == EXPECTED_MODULUS));
	}

	/* Add more tests as needed... */

	return EXIT_SUCCESS;
}
/**
 * test_myrsa_math.c - Unit tests for myrsa_math functions.
 *
 * Author: Benjamin Chin.
 */

#include <assert.h>
#include <stdlib.h>
#include "myrsa_math.h"

int main()
{
	assert(gcd(8, 12) == 4);
	assert(mod_inverse(7, 40) == 23);
	assert(extended_gcd(7, 40) == 23);

	/* Add more tests as needed... */

	return EXIT_SUCCESS;
}
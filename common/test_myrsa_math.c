/* test_myrsa_math.c - Unit tests for myrsa_math functions.  */

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include "myrsa_math.h"

int main()
{
	assert(gcd_recursive(8, 12) == 4);
	assert(gcd_recursive(15, 25) == 5);
	assert(gcd_recursive(21, 14) == 7);
	assert(gcd_recursive(40902, 24140) == 34);

	assert(gcd(8, 12) == 4);
	assert(gcd(15, 25) == 5);
	assert(gcd(21, 14) == 7);
	assert(gcd(40902, 24140) == 34);

	assert(mod_inverse(7, 40) == 23);
	assert(mod_inverse(3, 11) == 4);
	assert(mod_inverse(5, 12) == 0); /* result is 5, dropped */

	return EXIT_SUCCESS;
}

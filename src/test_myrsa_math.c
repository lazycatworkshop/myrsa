/**
 * test_myrsa_math.c - Unit tests for myrsa_math functions.
 */

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
	assert(mod_inverse(5, 12) == 0); /* No solution */

	int32_t x, y;
	assert(euclidean_algorithm_recursive(8, 12, &x, &y) == 4);
	assert(x == -1 && y == 1);
	assert(euclidean_algorithm_recursive(15, 25, &x, &y) == 5);
	assert(x == 2 && y == -1);
	assert(euclidean_algorithm_recursive(21, 14, &x, &y) == 7);
	assert(x == 1 && y == -1);
	assert(euclidean_algorithm_recursive(40902, 24140, &x, &y) == 34);

	assert(euclidean_algorithm(8, 12, &x, &y) == 4);
	assert(x == -1 && y == 1);
	assert(euclidean_algorithm(15, 25, &x, &y) == 5);
	assert(x == 2 && y == -1);
	assert(euclidean_algorithm(21, 14, &x, &y) == 7);
	assert(x == 1 && y == -1);
	assert(euclidean_algorithm(40902, 24140, &x, &y) == 34);

	return EXIT_SUCCESS;
}
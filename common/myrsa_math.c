#include <stdint.h>

/**
 * gcd_recursive - Calculate the greatest common divisor of two integers
 * 	recursively.
 * @u: First integer.
 * @v: Second integer.
 * 
 * 	This function calculates gcd using the Euclidean algorithm in a recursive
 * manner.
 * 
 * Return: The greatest common divisor.
 */
uint64_t gcd_recursive(uint64_t u, uint64_t v)
{
	if (v == 0)
		/* gcd(u, 0) = |u| */
		return u;
	else
		/* gcd(u, v) = gcd(v, u-qv) */
		return gcd_recursive(v, u % v);
}

/**
 * gcd - Calculate the greatest common divisor of two integers.
 * @a: First integer.
 * @b: Second integer.
 * 
 * This function calculates gcd using the Euclidean algorithm.
 * 
 * Return: The greatest common divisor.
 */
uint64_t gcd(uint64_t a, uint64_t b)
{
	uint64_t temp;
	while (b != 0) {
		temp = b;
		b = a % b;
		a = temp;
	}
	return a;
}

/**
 * mod_inverse - Calculate the modular inverse of a modulo m using brute force
 * 	method
 * @a: The integer for which the modular inverse is to be calculated
 * @m: The modulus
 *
 * This function iterates through all possible values of x from 1 to m-1 and
 * returns the first x such that (a * x) % m == 1.
 *
 * Returns: The modular inverse of a modulo m, or 0 if no such inverse exists.
 */
int64_t mod_inverse(uint64_t a, uint64_t m)
{
	for (uint64_t x = 2; x < m; x++) {
		if (((a * x) % m) == 1)
			if (a != x)
				return x;
	}

	return 0; /* No modular inverse exists */
}

/**
 * euclidean_algorithm_recursive - Calculate the greatest common divisor of
 *  	two integers using recursion.
 * @a: First integer.
 * @b: Second integer.
 * @x: Pointer to the Bézout coefficient x.
 * @y: Pointer to the Bézout coefficient y.
 * 
 * This function calculates the greatest common divisor of a and b using the
 * extended Euclidean algorithm recursively. It also calculates the Bézout
 * coefficients x and y such that ax + by = gcd(a, b).
 * 
 * Return: The greatest common divisor.
 * 
 * Note: The Bézout coefficients x and y are stored in the pointers x and y
 * respectively.
 * 
 */
uint64_t euclidean_algorithm_recursive(uint64_t a, uint64_t b, int32_t *x,
				       int32_t *y)
{
	if (b == 0) {
		*x = 1;
		*y = 0;
		return a;
	}

	int32_t x1, y1;
	uint64_t gcd = euclidean_algorithm_recursive(b, a % b, &x1, &y1);
	*x = y1;
	*y = x1 - (a / b) * y1;
	return gcd;
}

/**
 * euclidean_algorithm - Calculate the greatest common divisor of two integers
 * 			 using iteration.
 * @a: First integer.
 * @b: Second integer.
 * @x: Pointer to the Bézout coefficient x.
 * @y: Pointer to the Bézout coefficient y.
 * 
 * This function calculates the greatest common divisor of a and b using the
 * extended Euclidean algorithm iteratively. It also calculates the Bézout
 * coefficients x and y such that ax + by = gcd(a, b).
 * 
 * Return: The greatest common divisor.
 * 
 * Note: The Bézout coefficients x and y are stored in the pointers x and y
 * respectively.
 * 
 */
uint64_t euclidean_algorithm(uint64_t a, uint64_t b, int32_t *x, int32_t *y)
{
	int32_t x0 = 1, y0 = 0; /* Initially x and y when b is 0 */
	int32_t x1 = 0, y1 = 1; /* Next values of x and y */

	while (b != 0) {
		uint64_t q = a / b; /* Quotient */
		uint64_t r = a % b; /* Remainder */

		/* Update a and b for the next iteration */
		a = b;
		b = r;

		/* Temporary variables to hold previous state of x1 and y1 */
		int32_t tempX = x1, tempY = y1;

		/* Update x1 and y1 based on the quotient */
		x1 = x0 - q * x1;
		y1 = y0 - q * y1;

		/* Update x0 and y0 for the next iteration */
		x0 = tempX;
		y0 = tempY;
	}

	/* When b is 0, a is the GCD and the last valid coefficients are in
	   x0 and y0 */
	*x = x0;
	*y = y0;
	return a;
}

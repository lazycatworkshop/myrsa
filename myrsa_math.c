/**
 * myrsa_math.c - Implementation of math functions.
 *
 * Author: Benjamin Chin.
 */

/**
 * gcd - Calculate the greatest common divisor of two integers.
 * @a: First integer.
 * @b: Second integer.
 * Return: The greatest common divisor.
 */
int gcd(int a, int b)
{
	int temp;
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
 * 	returns the first x such that (a * x) % m == 1.
 *
 * Returns: The modular inverse of a modulo m, or -1 if no such inverse exists.
 */
int mod_inverse(int a, int m)
{
	int x;
	for (x = 1; x < m; x++)
		if ((a * x) % m == 1)
			return x;
	return -1;
}

/**
 * extended_gcd - Calculate the modular inverse of a modulo m using the
 * 	Extended Euclidean Algorithm
 * @a: The integer for which the modular inverse is to be calculated
 * @m: The modulus
 *
 * This function calculates the modular inverse of a modulo m using the
 * 	Extended Euclidean Algorithm. It returns the modular inverse of a
 * 	modulo m.
 *
 * Returns: The modular inverse of a modulo m.
 */
int extended_gcd(int a, int m)
{
	int m0 = m, t, q;
	int x0 = 0, x1 = 1;

	if (m == 1)
		return 0;

	/* Apply extended Euclid Algorithm */
	while (a > 1) {
		/* q is quotient */
		q = a / m;
		t = m;

		/* m is remainder now, process same as Euclid's algo */
		m = a % m, a = t;

		t = x0;
		x0 = x1 - q * x0;
		x1 = t;
	}

	/* Make x1 positive */
	if (x1 < 0)
		x1 += m0;

	return x1;
}

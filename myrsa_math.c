/**
 * myrsa_math.c - Implementation of math functions.
 *
 * Author: Benjamin Chin, ChatGPT.
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
 * modInverse - Calculate the modular multiplicative inverse of a number.
 * @a: Base number.
 * @m: Modulus.
 * Return: The modular multiplicative inverse, or -1 if it doesn't exist.
 */
int mod_inverse(int a, int m)
{
	int x;
	for (x = 1; x < m; x++)
		if ((a * x) % m == 1)
			return x;
	return -1;
}

/**
 * myrsa.c - Implementation of RSA functions.
 *
 * Author: Benjamin Chin.
 */

#include "myrsa_math.h"

/**
 * generate_RSA_keys - Generate RSA public and private keys.
 * @p: First prime number.
 * @q: Second prime number.
 * @n: Pointer to the modulus.
 * @e: Pointer to the encryption key.
 * @d: Pointer to the decryption key.
 * 
 * This function generates a pair of RSA keys, (e, n) and (d, n).
 * 
 * NOTE: Given the data type of n, make sure pick proper prime numbers
 * such that n does not overflow.
 */
void generate_RSA_keys(unsigned int p, unsigned int q, unsigned int *n,
		       unsigned int *e, unsigned int *d)
{
	/* First compute n as the product of two primes p and q */
	*n = p * q;

	/* Pick an integer e which is relatively prime to (p - 1) * (q - 1) */
	int phi = (p - 1) * (q - 1);
	*e = 2;
	while (gcd(*e, phi) != 1) {
		(*e)++;
	}

	/* Anoher integer d is the multiplicative inverse of e, modulo (p - 1)
	 * * (q - 1).
	 * That is:
	 * 	(e * d) % ((p - 1) * (q - 1)) = 1
	 */
	*d = mod_inverse(*e, phi);
}

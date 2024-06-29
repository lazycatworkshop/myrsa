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
 * @e: Pointer to the encryption key.
 * @d: Pointer to the decryption key.
 * @n: Pointer to the modulus.
 */
void generate_RSA_keys(int p, int q, int *e, int *d, int *n)
{
	int phi;

	/* First compute n as the product of two primes p and q */
	*n = p * q;

	/* Pick an integer e which is relatively prime to (p - 1) * (q - 1) */
	phi = (p - 1) * (q - 1);
	for (*e = 2; *e < phi; (*e)++) {
		if (gcd(*e, phi) == 1) {
			break;
		}
	}

	/* Anoher integer d is the multiplicative inverse of e, modulo (p - 1)
	 * * (q - 1).
	 * That is:
	 * 	(e * d) % ((p - 1) * (q - 1)) = 1
	 */
	*d = mod_inverse(*e, phi);
}

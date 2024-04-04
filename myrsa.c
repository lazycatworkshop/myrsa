/**
 * myrsa.c - Implementation of RSA functions.
 *
 * Author: Benjamin Chin, ChatGPT.
 */

#include "myrsa_math.h"

/**
 * generate_RSA_keys - Generate RSA public and private keys.
 * @p: First prime number.
 * @q: Second prime number.
 * @publicKey: Array to store the public key [0] = e, [1] = n.
 * @privateKey: Array to store the private key [0] = d, [1] = n.
 */
void generate_RSA_keys(int p, int q, int *publicKey, int *privateKey)
{
	int n;
	int phi;
	int e;
	int d;

	/* First compute n as the product of two primes p and q */
	n = p * q;

	/* Pick an integer e which is relatively prime to (p - 1) * (q - 1) */
	phi = (p - 1) * (q - 1);
	for (e = 2; e < phi; e++) {
		if (gcd(e, phi) == 1) {
			break;
		}
	}

	/* Anoher integer d is the multiplicative inverse of e, modulo (p - 1)
	 * * (q - 1).
	 * That is:
	 * 	(e * d) % ((p - 1) * (q - 1) = 1
	 */
	d = mod_inverse(e, phi);

	/* Let (e, n) be the public key */
	publicKey[0] = e;
	publicKey[1] = n;

	/* Let (d, n) be the private key */
	privateKey[0] = d;
	privateKey[1] = n;
}

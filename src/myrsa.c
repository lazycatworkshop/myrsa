/**
 * myrsa.c - Implementation of RSA functions.
 */
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include "myrsa_math.h"
#include "big_number.h"

static uint64_t max(uint64_t a, uint64_t b)
{
	return (a > b) ? a : b;
}

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
void generate_RSA_keys(uint64_t p, uint64_t q, uint64_t *n, uint64_t *e,
		       uint64_t *d)
{
	/* First compute n as the product of two primes p and q */
	*n = p * q;

	/* Pick an integer e which is relatively prime to (p - 1) * (q - 1) */
	uint64_t phi = (p - 1) * (q - 1);

	if (max(p, q) > 65535)
		*e = 65537; /* Use common public key for cases of big prime
				 numbers */
	else {
		*e = max(p, q) + 1;
		while (gcd(phi, *e) != 1)
			(*e)++;
	}

	/* Another integer d is the multiplicative inverse of e, modulo (p - 1)
	 * * (q - 1).
	 * That is:
	 *  (e * d) % ((p - 1) * (q - 1)) = 1
	 */
	*d = mod_inverse(*e, phi);
}

/**
 * RSA_trapdoor- Encrypt or decrypt a message by RSA.
 *
 * @message: The message.
 * @key: The key.
 * @modulus: The modulus.
 * 
 * This function uses exponentiation by "repeated squaring and multiplication
 * to compute C = M^key % modulus". The caller is responsible for ensuring
 * the input message is not greater than the modulus.
 * 
 * Return: The result of the modular exponentiation.
 */
uint64_t RSA_trapdoor(uint64_t message, uint64_t key, uint64_t modulus)
{
	uint64_t r = 1;
	while (key > 0) {
		if (key & 1) { /* Odd then multiply r by the current base */
			r = (r * message) % modulus;
		}
		message = (message * message) % modulus; /* Square */
		key >>= 1;
	}
	return r;
}

/**
 * RSA_trapdoor_big - Encrypt or decrypt a message by RSA.
 * 
 * @message: The message.
 * @key: The key.
 * @modulus: The modulus.
 * 
 * This function uses exponentiation by "repeated squaring and multiplication
 * to compute C = M^key % modulus". The caller is responsible for ensuring
 * the input message is not greater than the modulus.
 * 
 * Return: The result of the modular exponentiation.
 */
bn RSA_trapdoor_big(bn message, bn key, bn modulus)
{
	bn r = bn_from_int(1);
	while (bn_is_not_zero(&key)) {
		if (bn_is_odd(&key)) {
			r = bn_mod(bn_mul(r, message), modulus);
		}
		message = bn_mod(bn_mul(message, message), modulus);
		bn_right_shift(&key);
	}

	return r;
}
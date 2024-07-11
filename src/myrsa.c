/**
 * myrsa.c - Implementation of RSA functions.
 *
 * Author: Benjamin Chin.
 */
#include "myrsa_math.h"
#include <stddef.h>

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
void generate_RSA_keys(uint32_t p, uint32_t q, uint32_t *n, uint32_t *e,
		       uint32_t *d)
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

/**
 * RSA_trapdoor- Encrypt or decrypt a message by RSA.
 *
 * @message: The message.
 * @key: The key.
 * @modulus: The modulus.
 * 
 * This function uses exponentiation by "repeated squaring and multiplication
 *  	to compute C = M^key % modulus.
 * 
 * Return: The result of the modular exponentiation.
 */
uint64_t RSA_trapdoor(uint64_t message, uint64_t key, uint64_t modulus)
{
	uint64_t r = 1; /* when exponent is 0 */

	message = message % modulus;

	while (key > 0) {
		/* If LSB is 1,  multiply the base with result */
		if (key % 2 == 1)
			r = (r * message) % modulus;

		key = key >> 1; /* Next bit */
		message = (message * message) % modulus; /* Square */
	}

	return r;
}

/**
 * crc16_ccitt - Calculates the CRC-16-CCITT checksum.
 *
 * @param data Pointer to the data array.
 * @param len Length of the data array.
 * 
 * This function computes the cyclic redundancy check (CRC) checksum using the
 * CCITT-16 polynomial, 0x1021. This implementation starts with an initial
 * value of 0xFFFF and processes each byte of the input data array, bit by bit,
 * to compute the final CRC value.
 * 
 * @return The computed CRC16-CCITT checksum as a 16-bit unsigned integer.
 */
uint16_t crc16_ccitt(const char *data, size_t len)
{
#define CRC16_POLY 0x1021

	uint16_t crc = 0xFFFF;

	for (size_t i = 0; i < len; i++) {
		crc ^= (uint16_t)data[i] << 8;
		for (int j = 0; j < 8; j++) {
			if (crc & 0x8000)
				crc = (crc << 1) ^ CRC16_POLY;
			else
				crc <<= 1;
		}
	}

	return crc;
}

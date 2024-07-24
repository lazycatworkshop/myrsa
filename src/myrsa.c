/**
 * myrsa.c - Implementation of RSA functions.
 */
#include "myrsa_math.h"
#include <stddef.h>
#include <stdbool.h>

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
	else
		*e = max(p, q) + 1;

	while (gcd(phi, *e) != 1)
		(*e)++;

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
 *  	to compute C = M^key % modulus".
 * 
 * Return: The result of the modular exponentiation.
 */
uint64_t RSA_trapdoor(uint64_t message, uint64_t key, uint64_t modulus)
{
	uint64_t mask = 0x80000000;
	/* Skip the leading 0s */
	for (size_t i = 0; i < sizeof(uint64_t) * 8; i++) {
		if (key & mask) {
			break;
		}
		mask >>= 1;
	}

	uint64_t C = 1;
	while (mask) {
		C = (C * C) % modulus; /* Square */

		if (key & mask) {
			C = (C * message) % modulus; /* Multiplication */
		}

		mask >>= 1; /* Next bit */
	}

	return C;
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
#define CRC16_POLY 0x1021
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

static uint16_t crc16_table[256];
static int crc16_table_initialized = 0; /* If the table has been initialized */

void generate_crc16_table()
{
	for (int i = 0; i < 256; i++) {
		uint16_t crc = i << 8;
		for (int j = 0; j < 8; j++) {
			if (crc & 0x8000)
				crc = (crc << 1) ^ CRC16_POLY;
			else
				crc <<= 1;
		}
		crc16_table[i] = crc;
	}
	crc16_table_initialized = 1; /* The table is initialized */
}

uint16_t crc16_ccitt_table_lookup(const char *data, size_t len)
{
	if (!crc16_table_initialized) { /* If the table has not been initialized, */
		generate_crc16_table(); /* then initialize the table. */
	}

	uint16_t crc = 0xFFFF;

	for (size_t i = 0; i < len; i++) {
		uint8_t pos = (crc >> 8) ^ (uint8_t)data[i];
		crc = (crc << 8) ^ crc16_table[pos];
	}

	return crc;
}

/**
 * crc32 - Calculate the CRC-32 checksum for a given buffer
 * @data: pointer to the data buffer
 * @len: length of the data buffer
 *
 * This function calculates the CRC-32 checksum for a given data buffer
 * using a precomputed table based on the polynomial 0xEDB88320, IEEE 802.3.
 * The function iterates over each byte of the data, updating the CRC value
 * using the table lookup method. The final CRC value is inverted before
 * being returned.
 *
 * Return: The CRC-32 checksum of the data.
 */
#define CRC32_POLY 0xEDB88320

/* CRC-32 table for polynomial 0xEDB88320 */
static uint64_t crc32_table[256];
static int crc32_table_initialized = 0; /* If the table has been initialized */
/* Function to initialize the CRC-32 table */
void generate_crc32_table()
{
	for (uint64_t i = 0; i < 256; i++) {
		uint64_t crc = i;
		for (uint8_t j = 0; j < 8; j++) {
			if (crc & 1) {
				crc = (crc >> 1) ^ CRC32_POLY;
			} else {
				crc >>= 1;
			}
		}
		crc32_table[i] = crc;
	}
	crc32_table_initialized = 1; /* The table is initialized */
}

/**
 * crc32 - Calculate the CRC-32 checksum for a given buffer
 * @data: pointer to the data buffer
 * @len: length of the data buffer
 *
 * This function calculates the CRC-32 checksum for a given data buffer
 * using a precomputed table based on the polynomial 0xEDB88320, IEEE 802.3.
 * The function iterates over each byte of the data, updating the CRC value
 * using the table lookup method. The final CRC value is inverted before
 * being returned.
 *
 * Return: The CRC-32 checksum of the data.
 */
uint32_t crc32_b(const char *data, size_t len)
{
	if (!crc32_table_initialized) { /* If the table has not been initialized, */
		generate_crc32_table(); /* then initialize the table. */
	}

	uint32_t crc = 0xFFFFFFFF;

	for (size_t i = 0; i < len; i++) {
		uint8_t pos = (crc ^ (uint8_t)data[i]) & 0xFF;
		crc = (crc >> 8) ^ crc32_table[pos];
	}

	return crc ^ 0xFFFFFFFF;
}
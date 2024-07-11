#ifndef MYRSA_H
#define MYRSA_H

#include <stdint.h>
/**
 * myrsa.h - Header file for RSA key generation functions.
 *
 * Author: Benjamin Chin.
 */
void generate_RSA_keys(uint32_t p, uint32_t q, uint32_t *n, uint32_t *e,
		       uint32_t *d);

uint32_t crc16_ccitt(const char *data, size_t len);
uint64_t RSA_trapdoor(uint64_t message, uint64_t key, uint64_t modulus);

#endif /* MYRSA_H */

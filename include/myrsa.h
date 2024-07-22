#ifndef MYRSA_H
#define MYRSA_H

#include <stdint.h>
/**
 * myrsa.h - Header file for RSA key generation functions.
 *
 * Author: Benjamin Chin.
 */
void generate_RSA_keys(uint64_t p, uint64_t q, uint64_t *n, uint64_t *e,
		       uint64_t *d);

uint16_t crc16_ccitt(const char *data, size_t len);
uint16_t crc16_ccitt_table_lookup(const char *data, size_t len);
uint32_t crc32_b(const char *data, size_t len);
uint64_t RSA_trapdoor(uint64_t message, uint64_t key, uint64_t modulus);

#endif /* MYRSA_H */

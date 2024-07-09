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

#endif /* MYRSA_H */

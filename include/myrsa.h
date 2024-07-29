#ifndef MYRSA_H
#define MYRSA_H

#include <stdint.h>
/**
 * myrsa.h - Header file for RSA cryptography functions.
 */
void generate_RSA_keys(uint64_t p, uint64_t q, uint64_t *n, uint64_t *e,
		       uint64_t *d);
uint64_t RSA_trapdoor(uint64_t message, uint64_t key, uint64_t modulus);

#endif /* MYRSA_H */

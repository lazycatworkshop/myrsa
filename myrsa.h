#ifndef MYRSA_H
#define MYRSA_H

/**
 * myrsa.h - Header file for RSA key generation functions.
 *
 * Author: Benjamin Chin.
 */
void generate_RSA_keys(unsigned int p, unsigned int q, unsigned int *n,
		       unsigned int *e, unsigned int *d);

#endif /* MYRSA_H */

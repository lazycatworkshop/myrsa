#ifndef MYRSA_H
#define MYRSA_H

/**
 * myrsa.h - Header file for RSA key generation functions.
 *
 * Author: Benjamin Chin.
 */
void generate_RSA_keys(int p, int q, int *e, int *d, int *n);

#endif /* MYRSA_H */

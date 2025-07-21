#ifndef MYRSA_MATH_H
#define MYRSA_MATH_H

/**
 * myrsa_math.h - Header file for math functions.
 */

#include <stdint.h>

uint64_t gcd_recursive(uint64_t u, uint64_t v);
uint64_t gcd(uint64_t a, uint64_t b);
uint64_t mod_inverse(uint64_t a, uint64_t m);
uint64_t euclidean_algorithm_recursive(uint64_t a, uint64_t b, int32_t *x,
				       int32_t *y);
uint64_t euclidean_algorithm(uint64_t a, uint64_t b, int32_t *x, int32_t *y);

#endif /* MYRSA_MATH_H */

#ifndef MYRSA_MATH_H
#define MYRSA_MATH_H

/* myrsa_math.h - Header file for math functions. */

#include <stdint.h>

uint32_t gcd_recursive(uint32_t u, uint32_t v);
uint32_t gcd(uint32_t a, uint32_t b);
int32_t mod_inverse(uint32_t a, uint32_t m);
#if 0
uint64_t euclidean_algorithm_recursive(uint64_t a, uint64_t b, int32_t *x,
				       int32_t *y);
uint64_t euclidean_algorithm(uint64_t a, uint64_t b, int32_t *x, int32_t *y);
#endif

#endif /* MYRSA_MATH_H */

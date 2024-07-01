#ifndef MYRSA_MATH_H
#define MYRSA_MATH_H

/**
 * myrsa_math.h - Header file for math functions.
 *
 * Author: Benjamin Chin.
 */

#include <stdint.h>

uint32_t gcd(uint32_t a, uint32_t b);
uint32_t mod_inverse(uint32_t a, uint32_t m);
uint32_t euclidean_algorithm_recursive(uint32_t a, uint32_t b, int32_t *x,
				       int32_t *y);
uint32_t euclidean_algorithm(uint32_t a, uint32_t b, int32_t *x, int32_t *y);

#endif /* MYRSA_MATH_H */

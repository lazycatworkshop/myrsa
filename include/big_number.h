/** big_number.h - header file for big_number library.
 *    Assume big endian..
*/
#ifndef MYBN_H
#define MYBN_H

#include <stdint.h>
enum { MAX_DATA_SIZE = 1024 }; /* Enough for RSA 2048 */

typedef struct {
	size_t size;
	uint8_t data[MAX_DATA_SIZE];
} bn;

void bn_init(bn *a);
void bn_copy(bn *dest, bn *src);
bn bn_from_int(int64_t n);
void bn_to_string(bn *a, char *str, size_t len);
int bn_is_not_zero(bn *a);
int bn_is_odd(bn *a);
int bn_cmp(bn *a, bn *b);
void bn_left_shift(bn *a);
void bn_right_shift(bn *a);
void bn_inc(bn *a);
bn bn_add(bn a, bn b);
bn bn_sub(bn a, bn b);
bn bn_mul(bn a, bn b);
bn bn_mod(bn a, bn b);

#endif
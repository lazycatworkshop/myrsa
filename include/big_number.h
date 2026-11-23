/** big_number.h - header file for big_number library.
 *    Assume big endian..
*/
#ifndef MYBN_H
#define MYBN_H

#include <stdint.h>
#include <string.h>

enum { MAX_DATA_SIZE = 1024 }; /* Enough for RSA 2048 */

typedef struct {
	size_t size;
	uint8_t data[MAX_DATA_SIZE];
} bn;

void bn_init(bn *a);
void bn_copy(bn *dest, const bn *src);
bn bn_from_int(int64_t n);
void bn_to_string(const bn *a, char *str, size_t len);
int bn_is_not_zero(const bn *a);
int bn_is_odd(const bn *a);
int bn_cmp(const bn *a, const bn *b);
void bn_left_shift(bn *a);
void bn_right_shift(bn *a);
void bn_inc(bn *a);
bn bn_add(const bn *a, const bn *b);
bn bn_sub(const bn *a, const bn *b);
bn bn_mul(bn a, bn b);
/* void bn_div(bn *a, bn *b, bn *q, bn *r); */
bn bn_mod(bn a, bn b);

static inline int bn_is_zero(const bn *a)
{
	return !bn_is_not_zero(a);
}

static inline void trim_leading_zeros(bn *a)
{
#if 1
	size_t i = 0;
	while ((i < a->size) && (a->data[i] == 0)) {
		i++;
	}
	a->size -= i;
	memmove(a->data, a->data + i, a->size);

#else
	while (a->size > 1 && a->data[0] == 0) {
		a->size--;
		memmove(a->data, a->data + 1, a->size);
	}
#endif
}

#endif

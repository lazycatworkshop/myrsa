/** big_number.c - A library for RSA big number operations.
 * 
 * This library provides basic operations for big numbers used in this project.
 * It does not perform comprehensive error checking.
 *   
 * Assume unsigned values in big endian.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include "big_number.h"

/** bn_init - Zero-out a big number struct.
 * @a: The big number to be initialized.
 */
void bn_init(bn *a)
{
	a->size = 0;
	memset(a->data, 0, MAX_DATA_SIZE);
}

/** bn_copy - Copy a big number.
 * @dest: The destination big number.
 * @src: The source big number.
 */
void bn_copy(bn *dest, const bn *src)
{
	dest->size = src->size;
	memcpy(dest->data, src->data, dest->size);
}

/** bn_from_int - Create a big number from an unsigned integer.
 * @n: The integer to be converted.
 *
 * This function creates an integer up to 63 bit. One bit is reserved to
 * avoid overflow.
 */
bn bn_from_int(int64_t n)
{
	bn t;
	bn_init(&t);

	if (n) {
		t.size = sizeof(n);
		/* Store the data with big endian */
		for (size_t i = 0; i < t.size; i++) {
			t.data[i] = (n >> (8 * (t.size - i - 1))) & 0xff;
		}

		/* Trim the leading 0s */
		trim_leading_zeros(&t);
	} else {
		t.size = 1;
		t.data[0] = 0;
	}

	return t;
}

/** bn_to_string - Convert a big number to a string.
 * @a: The big number to be converted.
 * @str: The output string.
 * @len: The length of the output string.
 *
 * This function converts a big number to a hexadecimal string.
 */
void bn_to_string(const bn *a, char *str, size_t len)
{
	assert(a != NULL);
	assert(str != NULL);
	assert(len > 0);
	assert(a->size * 2 + 1 <= len); /* Plus NULL at the end */
	(void)len; /* Only used by assert */
	size_t i = 0;

	for (size_t j = 0; j < a->size; j++) {
		sprintf(&str[i], "%02X", a->data[j]);
		i += 2;
	}
	str[i] = '\0';
}

/** bn_is_not_zero - Check if a big number is not zero.
 * @a: The big number to be checked.
 *
 * This function checks if a big number is not zero.
 *
 * Return: 1 if the big number is not zero, 0 otherwise.
 *
 * NOTE: A zero can be any size.
 */
int bn_is_not_zero(const bn *a)
{
	for (size_t i = 0; i < a->size; i++) {
		if (a->data[i] != 0) {
			return 1;
		}
	}
	return 0;
}

/** bn_is_odd - Check if a big number is odd.
 * @a: The big number to be checked.
 *
 * This function checks if a big number is odd.
 *
 * Return: 1 if the big number is odd, 0 otherwise.
 */
int bn_is_odd(const bn *a)
{
	return a->data[a->size - 1] & 1;
}

/** bn_add - Add two big numbers.
 * @a: The first big number.
 * @b: The second big number.
 *
 * Assume big-endian.
 *
 * Return: The result of a + b.
 */
bn bn_add(const bn *a, const bn *b)
{
	bn temp;
	bn_init(&temp);

	if ((a->size == 0) && (b->size == 0))
		return temp;

	int i = a->size - 1;
	int j = b->size - 1;
	size_t size = a->size > b->size ? a->size : b->size;
	size++; /* Potential length */
	int k = size - 1; /* index to LSB */
	temp.size = size;

	uint16_t sum = 0;
	while (i >= 0 || j >= 0) {
		if (i >= 0) {
			sum += (uint16_t)a->data[i--];
		}
		if (j >= 0) {
			sum += (uint16_t)b->data[j--];
		}
		temp.data[k--] = sum & 0xff;
		sum >>= 8;
	}
	if (k >= 0) { /* No handling for overflow */
		temp.data[k] = sum;
	}

	trim_leading_zeros(&temp);

	return temp;
}

/** bn_comp - Make a 1's complement 
 * @a: The big number to be complemented.
 * 
 * This function computes the complement of a big number. It is used
 * in big number subtraction.
 */
void bn_comp(bn *a, size_t size)
{
	size_t i;

	if (a->size < size) {
		/* Expand the size */
		memmove(a->data + size - a->size, a->data, a->size);
		memset(a->data, 0, size - a->size);
		a->size = size;
	}

	/* 1's complement */
	for (i = 0; i < a->size; i++) {
		a->data[i] = ~a->data[i];
	}
}

/** bn_inc - Increment a big number
 * @a: The big number to be incremented.
 * 
 * This function increments a big number by 1.
 * 
 * NOTE: This function does not check for overflow.
 */
void bn_inc(bn *a)
{
	if (a->size) {
		/* Increment the LSB */
		uint16_t t = (uint16_t)a->data[a->size - 1] + 1;
		a->data[a->size - 1] = t & 0xff;
		t >>= 8;

		/* Propagate the carry */
		for (int i = a->size - 2; i >= 0; i--) {
			t = (uint16_t)a->data[i] + t;
			a->data[i] = t & 0xff;

			t >>= 8;
			if (!t) /* No more carry */ {
				break;
			}
		}

		/* If there is still a carry, we need to expand the size */
		if (t) {
			memmove(a->data + 1, a->data, a->size);
			a->data[0] = t & 0xff;
			a->size++;
		}

	} else {
		a->data[0] = 1;
		a->size = 1;
	}
}

/** bn_sub - This function subtract b from a 
 * @a: The first big number.
 * @b: The second big number.
 * 
 * This function calculate the result of a - b. Assume big-endian. A 2's
 * complement is used to as a reference.
 * 
 * The output size can be shorter as the result of the subtraction. Do not
 * trim the leading 0s to fit the use of the cryptographic operations.
 *  
 * Return: The result of a - b.
 */
bn bn_sub(const bn *a, const bn *b)
{
	bn c;
	bn_copy(&c, a);

	int borrow = 0;
	for (size_t i = 0; i < a->size; i++) {
		int subtrahend = i < b->size ? b->data[b->size - 1 - i] : 0;
		int diff = (int)c.data[c.size - 1 - i] - subtrahend - borrow;
		borrow = (diff < 0) ? 1 : 0;

		c.data[c.size - 1 - i] = ((diff + 256) % 256);
	}

	/* Do not trim leading 0s here */

	return c;
}

/** bn_mul - Multiply two big numbers.
 * @a: The first big number.
 * @b: The second big number.
 * 
 * Assume big-endian.
 * 
 * Return: The result of a * b.
 */
bn bn_mul(bn a, bn b)
{
	assert(!bn_is_zero(&a) || !bn_is_zero(&b));

	int i, j;
	uint8_t carry = 0;
	bn temp;
	bn_init(&temp);
	temp.size = a.size + b.size; /* Potential length */

	/* Multiply each digit of a with each digit of b.
	   LSB is at the end of data array. */
	for (i = a.size - 1; i >= 0; i--) {
		for (j = b.size - 1; j >= 0; j--) {
			uint16_t product = (uint16_t)a.data[i] * b.data[j];
			product += carry + temp.data[i + j + 1];
			temp.data[i + j + 1] = product & 0xff;
			carry = product >> 8;
		}
		temp.data[i + j + 1] = carry;
		carry = 0;
	}

	trim_leading_zeros(&temp);

	return temp;
}

/** bn_cmp - compare two big numbers
 * @a: The first big number.
 * @b: The second big number.
 * 
 * Assume big-endian.
 * 
 * Return: 1 if a > b, 0 if a == b, and -1 if a < b.
 * 
*/
int bn_cmp(const bn *a, const bn *b)
{
	size_t i = 0;
	size_t size_a = a->size;
	const uint8_t *p = a->data;
	while ((i < a->size) && (a->data[i] == 0)) {
		i++;
		size_a--;
		p++;
	}

	size_t size_b = b->size;
	const uint8_t *q = b->data;
	i = 0;
	while ((i < b->size) && (b->data[i] == 0)) {
		i++;
		size_b--;
		q++;
	}

	/* Compare the size */
	if (size_a > size_b) {
		return 1;
	} else if (size_a < size_b) {
		return -1;
	}

	/* Compare the data */
	for (i = 0; i < size_a; i++) {
		if (*p > *q) {
			return 1;
		} else if (*p < *q) {
			return -1;
		}
		p++;
		q++;
	}

	return 0;
}

/** bn_left_shift - Left shift a big number by 1 bit.
 * @a: The big number to be shifted.
 * 
 * This function shifts a big number to the left by 1 bit.
 * 
 * Assume big-endian.
 */
void bn_left_shift(bn *a)
{
	uint8_t carry = 0;
	for (int i = a->size; i > 0; i--) {
		uint16_t t = a->data[i - 1];
		t <<= 1;
		a->data[i - 1] = (t & 0xff) | carry;
		carry = t >> 8;
	}
}

/** bn_right_shift - Right shift a big number by 1 bit.
 * @a: The big number to be shifted.
 * 
 * This function shifts a big number to the right by 1 bit.
 * 
 * Assume big-endian.
 */
void bn_right_shift(bn *a)
{
	uint8_t carry = 0;
	for (size_t i = 0; i < a->size; i++) {
		uint8_t t = a->data[i];
		a->data[i] = (a->data[i] >> 1);
		a->data[i] |= carry << 7;
		carry = t & 1;
	}
}

/** bn_mod - Big Number modulation 
 * @a: The nominator.
 * @b: The divisor.
 * 
 * This function computes the remainder of a divided by b using long division.
 * A repeated subtraction method is present for reference.
 * 
 * NOTE: The result is adjusted to match the size of the divisor.
 * 
 * Assume big-endian.
 * 
 * Return: The remainder of a divided by b.
 */
bn bn_mod(bn a, bn b)
{
	assert(a.size);
	assert(!bn_is_zero(&b)); /* b must not be zero */

	bn r;

	int cmp_result = bn_cmp(&a, &b);
	if (cmp_result < 0) {
		/* a is less than b */
		bn_copy(&r, &a);
		goto post_process;
	}

	if (cmp_result == 0) {
		/* a is equal to b */
		bn_init(&r);
		goto post_process;
	}

#if 0
	/* Brutal force */
	bn_init(&r);
	bn_copy(&r, &a);
	while (bn_cmp(&r, &b) >= 0) {
		r = bn_sub(&r, &b);
	}
#else
	bn_init(&r);
	r.size = b.size;

	/* Loop at 1 bit step starting from msb */
	for (size_t i = 0; i < a.size * 8; i++) {
		/* Use r as the working nominator */
		/* The bit shifted out of r is lost when b has its msb set */
		int overflow = r.data[0] & 0x80;
		bn_left_shift(&r); /* lsb to hold msb of nominator */
		if (a.data[0] & 0x80) { /* Copy msb to the remainder */
			r.data[r.size - 1] |= 1;
		}

		/* Substract the divisor; r - b fits since r < 2 * b */
		if (overflow || bn_cmp(&r, &b) >= 0) {
			r = bn_sub(&r, &b);
		}

		/* Shift the divisor to the right */
		bn_left_shift(&a);
	}
#endif

post_process:

	if (bn_is_zero(&r)) {
		bn_init(&r);
		r.size = b.size; /* Match the size of the divisor */
		return r;
	}

	trim_leading_zeros(&r);

	/* Insert leading 0s to match the size of the divisor */
	size_t ins = r.size < b.size ? b.size - r.size : 0;
	if (ins) {
		memmove(r.data + ins, r.data, r.size);
		memset(r.data, 0, ins);
		r.size = b.size;
	}

	return r;
}

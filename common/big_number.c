/** big_number.c - A library for RSA big number operations.
 * 
 * This library provides basic operations for big numbers used in this project.
 * It does not perform comprehensive error checking.
 *   
 * Assume big endian.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "big_number.h"

void bn_init(bn *a)
{
	a->size = 0;
	memset(a->data, 0, MAX_DATA_SIZE);
}

void bn_copy(bn *dest, bn *src)
{
	dest->size = src->size;
	memcpy(dest->data, src->data, dest->size);
}

bn bn_from_int(int64_t n)
{
	bn t;
	t.size = sizeof(n);
	/* Store the data with big endian */
	for (size_t i = 0; i < t.size; i++) {
		t.data[i] = (n >> (8 * (t.size - i - 1))) & 0xff;
	}

	/* Trim the leading 0s */
	while (t.size > 1 && t.data[0] == 0) {
		t.size--;
		memmove(t.data, t.data + 1, t.size);
	}

	return t;
}

void bn_to_string(bn *a, char *str, size_t len)
{
	if (a->size * 2 + 1 > len) { /* Plus NULL at the end */
		fprintf(stderr, "Error: buffer too small\n");
		return;
	}

	size_t i = 0;

	for (size_t j = 0; j < a->size; j++) {
		sprintf(&str[i], "%02x", a->data[j]);
		i += 2;
	}
	str[i] = '\0';
}

int bn_is_not_zero(bn *a)
{
	for (size_t i = 0; i < a->size; i++) {
		if (a->data[i] != 0) {
			return 1;
		}
	}
	return 0;
}

int bn_is_odd(bn *a)
{
	return a->data[a->size - 1] & 1;
}

bn bn_add(bn a, bn b)
{
	bn temp;
	bn_init(&temp);

	if ((a.size == 0) && (b.size == 0))
		return temp;

	int i = a.size - 1;
	int j = b.size - 1;
	size_t size = a.size > b.size ? a.size : b.size;
	size++; /* Potential length */
	int k = size - 1;

	uint16_t sum = 0;
	while (i >= 0 || j >= 0) {
		if (i >= 0) {
			sum += (uint16_t)a.data[i--];
		}
		if (j >= 0) {
			sum += (uint16_t)b.data[j--];
		}
		temp.data[k--] = sum & 0xff;
		sum >>= 8;
	}
	if (k >= 0) { /* No handling for overflow */
		temp.data[k] = sum;
	}

	/* Trim the leading 0s */
	i = 0;
	while (temp.data[i] == 0) {
		i++;
	}
	if (i) {
		size -= i;
		memmove(temp.data, temp.data + i, size);
	}

	temp.size = size;

	return temp;
}

/* bn_comp - Make a 1's complement 
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

/* bn_inc - Increment a big number
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
		int16_t t = (uint16_t)a->data[a->size - 1] + 1;
		a->data[a->size - 1] = t & 0xff;
		t >>= 8;

		/* Propagate the carry */
		for (size_t i = a->size - 2; i >= 0; i--) {
			t = (uint16_t)a->data[i] + t;
			a->data[i] = t & 0xff;

			t >>= 8;
			if (!t) /* No more carry */ {
				break;
			}
		}
	} else {
		a->data[0] = 1;
		a->size = 1;
	}
}

/* bn_sub - This function subtract b from a 
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
bn bn_sub(bn a, bn b)
{
#if 0
	bn temp;
	bn_comp(&b, a.size);
	temp = bn_add(a, b);
	/* Eliminate the overflow */
	if (temp.size > a.size) {
		temp.data[0] = 0;
		temp.size--;
		memmove(temp.data, temp.data + 1, temp.size);
	}
	bn_inc(&temp);
#else

	int borrow = 0;
	for (size_t i = 0; i < a.size; i++) {
		int subtrahend = i < b.size ? b.data[b.size - 1 - i] : 0;
		int diff = (int)a.data[a.size - 1 - i] - subtrahend - borrow;
		borrow = (diff < 0) ? 1 : 0;

		a.data[a.size - 1 - i] = ((diff + 256) % 256);
	}

#endif

	/* Do not trim leading 0s here */

	return a;
}

/* bn_mul - Multiply two big numbers.
 * @a: The first big number.
 * @b: The second big number.
 * 
 * Assume big-endian.
 * 
 * Return: The result of a * b.
 */
bn bn_mul(bn a, bn b)
{
	if (bn_is_not_zero(&a) == 0 || bn_is_not_zero(&b) == 0) {
		return a;
	}

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

	/* Trim the leading 0s */
	i = 0;
	while (temp.data[i] == 0) {
		i++;
	}
	if (i) {
		temp.size -= i;
		memmove(temp.data, temp.data + i, temp.size);
	}

	return temp;
}

/* bn_cmp - compare two big numbers
 * @a: The first big number.
 * @b: The second big number.
 * 
 * Assume big-endian.
 * 
 * Return: 1 if a > b, 0 if a == b, and -1 if a < b.
 * 
*/
int bn_cmp(bn *a, bn *b)
{
	int i = 0;
	size_t size_a = a->size;
	uint8_t *p = a->data;
	while ((i < a->size) && (a->data[i] == 0)) {
		i++;
		size_a--;
		p++;
	}

	size_t size_b = b->size;
	uint8_t *q = b->data;
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

/* bn_left_shift - Left shift a big number by 1 bit.
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

/* bn_right_shift - Right shift a big number by 1 bit.
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

/* bn_mod - Big Number modulation 
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
	bn r;
	bn_init(&r);
	r.size = b.size;

	int cmp_result = bn_cmp(&a, &b);
	if (cmp_result < 0) {
		/* a is less than b */
		bn_copy(&r, &a);

		/* Insert leading 0s if necessary */
		size_t i = 0;
		while ((i < r.size) && (r.data[i] == 0)) {
			i++;
		}
		/* Insert leading 0s: j + (r.size -i) = b.size */
		int j = b.size - (r.size - i);
		memmove(r.data + j, r.data, r.size);
		r.size = b.size;

		return r;
	} else if (cmp_result == 0) {
		return r;
	}

#if 0
	while (bn_cmp(&a, &b) >= 0) {
		a = bn_sub(a, b);
	}

	return a;
#else
	r.size = a.size;
	/* Loop at 1 bit step starting from msb */
	for (int i = 0; i < a.size * 8; i++) {
		/* Build temp nominator */
		bn_left_shift(&r); /* lsb will hold the current bit of a */
		if (a.data[0] & 0x80) { /* If the current position at a is 1 */
			r.data[r.size - 1] |= 1; /* Copy it to r */
		}

		/* Subtract if possible */
		if (bn_cmp(&r, &b) >= 0) {
			r = bn_sub(r, b);
		}

		/* Shift the nominator,
		   it is like shifting the divisor to the right in manual calculation. */
		bn_left_shift(&a);
	}

	/* Trim the leading 0s */
	int i = 0;
	while ((i < r.size) && (r.data[i] == 0)) {
		i++;
	}
	if (i) {
		if ((r.size - i) >= b.size) { /* No less than the modulus */
			r.size -= i;
			memmove(r.data, r.data + i, r.size);
		} else { /* Less than the modulus */
			/* Insert leading 0s: j + (r.size -i) = b.size */
			int j = b.size - (r.size - i);
			memmove(r.data + j, r.data + i, r.size - i);
			r.size = b.size;
		}
	}

	return r;
#endif
}

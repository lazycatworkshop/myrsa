/* pem_der.c - Functions for handling PEM and DER encoded data */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define NOT_B64 (64) /* Any random value > 63 */
/* The printable characters is a subset of ASCII */
static const uint8_t ascii2bin_table[128] = {
	/*  Base64 ASCII */
	NOT_B64, /* 0x00 */
	NOT_B64, /* 0x01 */
	NOT_B64, /* 0x02 */
	NOT_B64, /* 0x03 */
	NOT_B64, /* 0x04 */
	NOT_B64, /* 0x05 */
	NOT_B64, /* 0x06 */
	NOT_B64, /* 0x07 */
	NOT_B64, /* 0x08 */
	NOT_B64, /* 0x09 */
	NOT_B64, /* 0x0A */
	NOT_B64, /* 0x0B */
	NOT_B64, /* 0x0C */
	NOT_B64, /* 0x0D */
	NOT_B64, /* 0x0E */
	NOT_B64, /* 0x0F */
	NOT_B64, /* 0x10 */
	NOT_B64, /* 0x11 */
	NOT_B64, /* 0x12 */
	NOT_B64, /* 0x13 */
	NOT_B64, /* 0x14 */
	NOT_B64, /* 0x15 */
	NOT_B64, /* 0x16 */
	NOT_B64, /* 0x17 */
	NOT_B64, /* 0x18 */
	NOT_B64, /* 0x19 */
	NOT_B64, /* 0x1A */
	NOT_B64, /* 0x1B */
	NOT_B64, /* 0x1C */
	NOT_B64, /* 0x1D */
	NOT_B64, /* 0x1E */
	NOT_B64, /* 0x1F */
	NOT_B64, /* 0x20 */
	NOT_B64, /* 0x21 */
	NOT_B64, /* 0x22 */
	NOT_B64, /* 0x23 */
	NOT_B64, /* 0x24 */
	NOT_B64, /* 0x25 */
	NOT_B64, /* 0x26 */
	NOT_B64, /* 0x27 */
	NOT_B64, /* 0x28 */
	NOT_B64, /* 0x29 */
	NOT_B64, /* 0x2A */
	62, /* 0x2B - '+' */
	NOT_B64, /* 0x2C */
	NOT_B64, /* 0x2D */
	NOT_B64, /* 0x2E */
	63, /* 0x2F - '/' */
	52, /* 0x30 - '0' */
	53, /* 0x31 - '1' */
	54, /* 0x32 - '2' */
	55, /* 0x33 - '3' */
	56, /* 0x34 - '4' */
	57, /* 0x35 - '5' */
	58, /* 0x36 - '6' */
	59, /* 0x37 - '7' */
	60, /* 0x38 - '8' */
	61, /* 0x39 - '9' */
	NOT_B64, /* 0x3A */
	NOT_B64, /* 0x3B */
	NOT_B64, /* 0x3C */
	NOT_B64, /* 0x3D */
	NOT_B64, /* 0x3E */
	NOT_B64, /* 0x3F */
	NOT_B64, /* 0x40 */
	0, /* 0x41 - 'A' */
	1, /* 0x42 - 'B' */
	2, /* 0x43 - 'C' */
	3, /* 0x44 - 'D' */
	4, /* 0x45 - 'E' */
	5, /* 0x46 - 'F' */
	6, /* 0x47 - 'G' */
	7, /* 0x48 - 'H' */
	8, /* 0x49 - 'I' */
	9, /* 0x4A - 'J' */
	10, /* 0x4B - 'K' */
	11, /* 0x4C - 'L' */
	12, /* 0x4D - 'M' */
	13, /* 0x4E - 'N' */
	14, /* 0x4F - 'O' */
	15, /* 0x50 - 'P' */
	16, /* 0x51 - 'Q' */
	17, /* 0x52 - 'R' */
	18, /* 0x53 - 'S' */
	19, /* 0x54 - 'T' */
	20, /* 0x55 - 'U' */
	21, /* 0x56 - 'V' */
	22, /* 0x57 - 'W' */
	23, /* 0x58 - 'X' */
	24, /* 0x59 - 'Y' */
	25, /* 0x5A - 'Z' */
	NOT_B64, /* 0x5B */
	NOT_B64, /* 0x5C */
	NOT_B64, /* 0x5D */
	NOT_B64, /* 0x5E */
	NOT_B64, /* 0X5F */
	NOT_B64, /* 0x60 */
	26, /* 0x61 - 'a' */
	27, /* 0x62 - 'b' */
	28, /* 0x63 - 'c' */
	29, /* 0x64 - 'd' */
	30, /* 0x65 - 'e' */
	31, /* 0x66 - 'f' */
	32, /* 0x67 - 'g' */
	33, /* 0x68 - 'h' */
	34, /* 0x69 - 'i' */
	35, /* 0x6A - 'j' */
	36, /* 0x6B - 'k' */
	37, /* 0x6C - 'l' */
	38, /* 0x6D - 'm' */
	39, /* 0x6E - 'n' */
	40, /* 0x6F - 'o' */
	41, /* 0x70 - 'p' */
	42, /* 0x71 - 'q' */
	43, /* 0x72 - 'r' */
	44, /* 0x73 - 's' */
	45, /* 0x74 - 't' */
	46, /* 0x75 - 'u' */
	47, /* 0x76 - 'v' */
	48, /* 0x77 - 'w' */
	49, /* 0x78 - 'x' */
	50, /* 0x79 - 'y' */
	51, /* 0x7A - 'z' */
	NOT_B64, /* 0x7B */
	NOT_B64, /* 0x7C */
	NOT_B64, /* 0x7D */
	NOT_B64, /* 0x7E */
	NOT_B64 /* 0x7F */
};

/** pem2der - Convert a line of PEM (Base64) to DER (binary)
 * @pem: Input PEM string
 * @der: Output buffer for DER data
 * @der_len: Pointer to size of output buffer, updated with actual length
 * 
 * NOTE: Does not expect PEM headers or footers
 * 
 * Returns 0 on success, -1 on error
 */
int pem2der(const char *pem, uint8_t der[], size_t *der_len)
{
	if (!pem || strlen(pem) == 0)
		return -1;

	if (!der || !der_len || *der_len < (strlen(pem) / 4 * 3))
		return -2;

	*der_len = 0;

	/* 4 6-bit bytes -> 3 8-bit bytes */
	for (size_t i = 0; i < strlen(pem) / 4; i++) {
		uint8_t a, b, c, d;
		a = ascii2bin_table[(uint8_t)pem[i * 4 + 0]];
		b = ascii2bin_table[(uint8_t)pem[i * 4 + 1]];
		c = ascii2bin_table[(uint8_t)pem[i * 4 + 2]];
		d = ascii2bin_table[(uint8_t)pem[i * 4 + 3]];

		if (a == NOT_B64 || b == NOT_B64)
			return -3;

		der[*der_len] = (a << 2) | (b >> 4);
		++*der_len;

		if (pem[i * 4 + 2] != '=') { /* 1st padding character */
			if (c == NOT_B64)
				return -4;

			der[*der_len] = (b << 4) | (c >> 2);
			++*der_len;
		}
		if (pem[i * 4 + 3] != '=') { /* 2nd padding character */
			if (d == NOT_B64)
				return -5;

			der[*der_len] = (c << 6) | d;
			++*der_len;
		}
	}

	return 0;
}

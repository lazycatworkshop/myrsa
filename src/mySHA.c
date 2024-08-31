/** SHA.c - SHA library
 * Reference: 
 *      https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 *      https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "mySHA.h"

/***** SHA-256 *****/
uint32_t SHA256_K[] = {
	0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
	0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
	0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
	0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
	0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
	0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
	0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
	0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
	0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
	0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
	0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

uint32_t Ch(uint32_t x, uint32_t y, uint32_t z)
{
	return (x & y) ^ (~x & z);
};

uint32_t Maj(uint32_t x, uint32_t y, uint32_t z)
{
	return (x & y) ^ (x & z) ^ (y & z);
};

uint32_t ROTR(uint32_t x, uint32_t n)
{
	return (x >> n) | (x << (32 - n));
};

uint32_t SHR(uint32_t x, uint32_t n)
{
	return x >> n;
};

uint32_t Sigma0(uint32_t x)
{
	return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
};

uint32_t Sigma1(uint32_t x)
{
	return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
};

uint32_t sigma0(uint32_t x)
{
	return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3);
};

uint32_t sigma1(uint32_t x)
{
	return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10);
};

/**
 * @brief Process a block of 512 bits.
 * 
 * @param M Message block.
 * @param H Hash value[O].
 * 
 */
void SHA256_process_block(uint32_t M[], uint32_t H[])
{
	uint32_t W[64]; /* message schedule */
	uint32_t a, b, c, d, e, f, g, h; /* working variables */

	int t;

	for (t = 0; t < 16; t++) {
		W[t] = M[t];
	}

	for (t = 16; t < 64; t++) {
		W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) +
		       W[t - 16];
	}

	a = H[0];
	b = H[1];
	c = H[2];
	d = H[3];
	e = H[4];
	f = H[5];
	g = H[6];
	h = H[7];

	for (t = 0; t < 64; t++) {
		uint32_t T1, T2;
		T1 = h + Sigma1(e) + Ch(e, f, g) + SHA256_K[t] + W[t];
		T2 = Sigma0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	H[0] += a;
	H[1] += b;
	H[2] += c;
	H[3] += d;
	H[4] += e;
	H[5] += f;
	H[6] += g;
	H[7] += h;
};

uint32_t endian_swap_32(uint32_t x)
{
	return (x >> 24) | ((x >> 8) & 0x0000FF00) | ((x << 8) & 0x00FF0000) |
	       (x << 24);
};

#define ENDIAN_SWAP_32(x)                                                      \
	(((x) >> 24) | (((x) >> 8) & 0x0000FF00) | (((x) << 8) & 0x00FF0000) | \
	 ((x) << 24))

void SHA256_init(uint32_t H[])
{
	H[0] = 0x6A09E667;
	H[1] = 0xBB67AE85;
	H[2] = 0x3C6EF372;
	H[3] = 0xA54FF53A;
	H[4] = 0x510E527F;
	H[5] = 0x9B05688C;
	H[6] = 0x1F83D9AB;
	H[7] = 0x5BE0CD19;
};

/**
 * @brief Compute the SHA-256 hash of a message.
 * 
 * @param msg Message to be hashed.
 * @param len Length of the message in bytes.
 * @param H Hash value[O].
 * 
 * @return void
 * 
 */
void SHA256_compute_hash(char msg[], size_t len, uint32_t H[])
{
	SHA256_init(H);

	uint32_t M[SHA256_BLOCK_SIZE / 8]; /* message block */
	size_t offset = 0; /* pointer for processed input message */
	size_t remaining = len; /*input message to be processed */

	while (remaining >= SHA256_BLOCK_SIZE / 8) {
		/* Inline parsing */
		uint32_t *p = (uint32_t *)msg;
		uint32_t *m = M;
		for (size_t i = 0; i < 16; i++) {
			*m = (((*p) >> 24) | (((*p) >> 8) & 0x0000FF00) |
			      (((*p) << 8) & 0x00FF0000) | ((*p) << 24));
			p++;
			m++;
		}
		SHA256_process_block(M, H);
		remaining -= SHA256_BLOCK_SIZE << 3; /* 8 bits/byte */
	}

	/* Padding */
	if (remaining > 0) {
		memset(M, 0, sizeof(M));
		/* Remanent */
		for (size_t i = 0; i < remaining; i++) {
			M[i / 4] |= msg[offset++] << (24 - 8 * (i % 4));
		}
	}

	/* Append 1 bit */
	M[remaining / 4] |= 0x80 << (24 - 8 * (remaining % 4));

	/* Append length */
	if (remaining >= 56) { /* > 512-64=448 bits, length is in a new block */
		SHA256_process_block(M, H);
		memset(M, 0, sizeof(M));
	}

	/* Length is in the last 64  bits */
	M[14] = (len >> 29);
	M[15] = (len << 3);
	SHA256_process_block(M, H);
};

void SHA256_get_digest(uint32_t H[], uint8_t digest[])
{
	/* Concatenate hash values in big endian */
	for (int i = 0; i < SHA256_WORD_COUNT; i++) {
		digest[i * 4] = (H[i] >> 24) & 0xFF;
		digest[i * 4 + 1] = (H[i] >> 16) & 0xFF;
		digest[i * 4 + 2] = (H[i] >> 8) & 0xFF;
		digest[i * 4 + 3] = H[i] & 0xFF;
	}
};

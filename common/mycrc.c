/* mycrc.c - Table-free CRC-16 (CCITT) and CRC-32
 *
 * CRC basics:
 *   Treat the message as one long binary polynomial over GF(2) (coefficients
 *   are 0/1, addition is XOR, no carries). The CRC is the remainder of
 *   dividing that polynomial (shifted left by the CRC width) by a fixed
 *   "generator" polynomial. The hardware-style long division is:
 *
 *     for each message bit:
 *         shift the register by one bit;
 *         if a 1 was shifted out of the top, XOR the generator into the register.
 *
 *   Processing a whole byte at a time is the same as doing that 8 times, so
 *   we XOR the byte into the register first and then run 8 shift/XOR steps.
 *   (Table-driven CRCs just precompute the result of these 8 steps per byte;
 *   here we compute them directly.)
 *
 *   The generator's top bit (x^16 or x^32) is implicit: it is exactly the
 *   bit that gets shifted out, so only the lower bits are stored.
 */
#include <stddef.h>
#include <stdint.h>
#include "mycrc.h"

/* CRC-16/CCITT-FALSE
 * Generator x^16 + x^12 + x^5 + 1 -> 0x1021 (top x^16 implicit).
 * Non-reflected (MSB first): the register shifts left and message bytes
 * enter at the top of the register.
 */
uint16_t crc16_ccitt(const uint8_t *data, size_t len)
{
	uint16_t crc = 0xFFFF; /* init value */
	size_t i;
	int bit;

	for (i = 0; i < len; i++) {
		/* Align the byte with the top 8 bits of the register. */
		crc ^= (uint16_t)((uint16_t)data[i] << 8);

		for (bit = 0; bit < 8; bit++) {
			if (crc & 0x8000) /* a 1 is about to be shifted out */
				crc = (uint16_t)((crc << 1) ^ 0x1021);
			else
				crc = (uint16_t)(crc << 1);
		}
	}

	return crc; /* no final XOR */
}

/* CRC-32 (IEEE 802.3)
 * Generator x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 +
 * x^7 + x^5 + x^4 + x^2 + x + 1 -> 0x04C11DB7.
 * The algorithm is "reflected" (LSB first): bytes enter the low end of the
 * register and it shifts right, so the generator's bits are mirrored:
 * 0x04C11DB7 -> 0xEDB88320.
 */
uint32_t crc32(const uint8_t *data, size_t len)
{
	uint32_t crc = 0xFFFFFFFFu; /* init value */
	size_t i;
	int bit;

	for (i = 0; i < len; i++) {
		/* Align the byte with the low 8 bits of the register. */
		crc ^= data[i];

		for (bit = 0; bit < 8; bit++) {
			if (crc & 1u) /* a 1 is about to be shifted out */
				crc = (crc >> 1) ^ 0xEDB88320u;
			else
				crc >>= 1;
		}
	}

	return crc ^ 0xFFFFFFFFu; /* final XOR */
}

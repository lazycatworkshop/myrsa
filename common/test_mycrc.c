/* test_mycrc.c - Test for CRC-16 (CCITT) and CRC-32 */
/* assert() is required */
#if defined(NDEBUG)
#define RESTORE_ASSERT
#undef NDEBUG
#endif

#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "mycrc.h"

static void test_crc16_ccitt(void)
{
	const char *check = "123456789";
	uint8_t zeros[4] = { 0, 0, 0, 0 };

	/* Empty input returns the init value */
	assert(crc16_ccitt((const uint8_t *)"", 0) == 0xFFFF);

	/* Standard check value for CRC-16/CCITT-FALSE */
	assert(crc16_ccitt((const uint8_t *)check, strlen(check)) == 0x29B1);

	assert(crc16_ccitt((const uint8_t *)"A", 1) == 0xB915);
	assert(crc16_ccitt(zeros, sizeof(zeros)) == 0x84C0);

	/* Appending the CRC (big-endian) to the message yields a zero CRC */
	{
		uint8_t buf[11];
		uint16_t crc = crc16_ccitt((const uint8_t *)check, 9);

		memcpy(buf, check, 9);
		buf[9] = (uint8_t)(crc >> 8);
		buf[10] = (uint8_t)(crc & 0xFF);
		assert(crc16_ccitt(buf, sizeof(buf)) == 0);
	}
}

static void test_crc32(void)
{
	const char *check = "123456789";
	const char *fox = "The quick brown fox jumps over the lazy dog";
	uint8_t zeros[4] = { 0, 0, 0, 0 };

	/* Empty input -> 0 */
	assert(crc32((const uint8_t *)"", 0) == 0x00000000u);

	/* Standard check value for CRC-32 */
	assert(crc32((const uint8_t *)check, strlen(check)) == 0xCBF43926u);

	assert(crc32((const uint8_t *)"a", 1) == 0xE8B7BE43u);
	assert(crc32((const uint8_t *)fox, strlen(fox)) == 0x414FA339u);
	assert(crc32(zeros, sizeof(zeros)) == 0x2144DF1Cu);
}

int main(void)
{
	test_crc16_ccitt();
	test_crc32();

	return 0;
}

#ifdef RESTORE_ASSERT
#define NDEBUG
#undef RESTORE_ASSERT
#endif

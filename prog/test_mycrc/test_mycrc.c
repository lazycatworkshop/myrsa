/**
 * test_mycrc.c - Unit tests for mycrc functions.
 */

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include "mycrc.h"

void test_crc()
{
	assert(crc16_ccitt("", 0) == 0xFFFF);
	assert(crc16_ccitt("a", 1) == 0x9D77);
	assert(crc16_ccitt("The quick brown fox jumps over the lazy dog", 43) ==
	       0x8FDD);

	assert(crc32("", 0) == 0x0);
	assert(crc32("The quick brown fox jumps over the lazy dog", 43) ==
	       0x414FA339);
}

int main()
{
	test_crc();

	/* Add calls to more test functions as needed... */

	return EXIT_SUCCESS;
}
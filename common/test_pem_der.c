/* test_pem_der.c - Test for PEM to DER conversion */
/* assert() is required */
#if defined(NDEBUG)
#define RESTORE_ASSERT
#undef NDEBUG
#endif

#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "pem_der.h"

void test_pem2der(void)
{
	uint8_t buffer[MAX_DER_BUFFER_SIZE];
	size_t len;

	/* 1. Error Handling & Validation Tests */
	len = sizeof(buffer);
	assert(pem2der(NULL, buffer, &len) == -1);

	len = sizeof(buffer);
	assert(pem2der("", buffer, &len) == -1);

	len = sizeof(buffer);
	assert(pem2der("TWFu", NULL, &len) == -2);

	assert(pem2der("TWFu", buffer, NULL) == -2);

	len = 1; /* Too small for standard base64 expansion */
	assert(pem2der("TWFu", buffer, &len) == -2);

	len = sizeof(buffer);
	assert(pem2der("TWM!", buffer, &len) == -5);

	/* 2. Binary Value Verification Tests */

	/* Test A: Standard Base64 string "TWFu" -> decodes to ASCII "Man"
         * (Bytes: 0x4D, 0x61, 0x6E)
         */
	memset(buffer, 0, sizeof(buffer));
	len = sizeof(buffer);
	assert(pem2der("TWFu", buffer, &len) == 0);
	assert(len == 3);
	assert(buffer[0] == 0x4D); /* 'M' */
	assert(buffer[1] == 0x61); /* 'a' */
	assert(buffer[2] == 0x6E); /* 'n' */

	/* Test B: Base64 string with 1 padding character ('=') -> "QVBJ" / "QVBK" etc.
         * Let's test "SGk=" -> decodes to ASCII "Hi" (Bytes: 0x48, 0x69)
         */
	memset(buffer, 0, sizeof(buffer));
	len = sizeof(buffer);
	assert(pem2der("SGk=", buffer, &len) == 0);
	assert(len == 2);
	assert(buffer[0] == 0x48); /* 'H' */
	assert(buffer[1] == 0x69); /* 'i' */

	/* Test C: Base64 string with 2 padding characters ('==') -> "YQ=="
         * -> decodes to "a" (Byte: 0x61)
         */
	memset(buffer, 0, sizeof(buffer));
	len = sizeof(buffer);
	assert(pem2der("YQ==", buffer, &len) == 0);
	assert(len == 1);
	assert(buffer[0] == 0x61); /* 'a' */

	/* Test D: Numeric/Hex block -> "MDEyMzQ1Njc=" -> decodes to ASCII
         * "01234567"
         */
	memset(buffer, 0, sizeof(buffer));
	len = sizeof(buffer);
	assert(pem2der("MDEyMzQ1Njc=", buffer, &len) == 0);
	assert(len == 8);
	assert(buffer[0] == '0'); /* 0x30 */
	assert(buffer[1] == '1');
	assert(buffer[2] == '2');
	assert(buffer[3] == '3');
	assert(buffer[4] == '4');
	assert(buffer[5] == '5');
	assert(buffer[6] == '6');
	assert(buffer[7] == '7');
}

int main(void)
{
	test_pem2der();

	return 0;
}

#ifdef RESTORE_ASSERT
#define NDEBUG
#undef RESTORE_ASSERT
#endif
/* test_mySHA.c - Test suite for mySHA.c */

#if defined(NDEBUG)
#define RESTORE_NDEBUG
#undef NDEBUG
#endif

#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "mySHA.h"

/* Most systems are little endian */
static int is_little_endian(void)
{
	union {
		uint32_t i;
		char c[4];
	} test_union = { 0x01020304 };

	return test_union.c[0] == 4;
}

/* Reference: 
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
 */
static void test_SHA256()
{
	uint32_t H[SHA256_WORD_COUNT];

	const char *message = "abc"; /* < 448 bits */
	SHA256_compute_hash((const uint8_t *)message, strlen(message), H);
	assert(H[0] == 0xba7816bf);
	assert(H[1] == 0x8f01cfea);
	assert(H[2] == 0x414140de);
	assert(H[3] == 0x5dae2223);
	assert(H[4] == 0xb00361a3);
	assert(H[5] == 0x96177a9c);
	assert(H[6] == 0xb410ff61);
	assert(H[7] == 0xf20015ad);

	uint8_t digest[SHA256_DIGEST_SIZE / 8]; /* In bytes */
	SHA256_get_digest(H, digest);
	uint32_t *p = (uint32_t *)digest;
	if (is_little_endian()) { /* Most systems are little endian */
		/* Convert H to little endian */
		assert(p[0] == 0xbf1678ba);
		assert(p[1] == 0xeacf018f);
		assert(p[2] == 0xde404141);
		assert(p[3] == 0x2322ae5d);
		assert(p[4] == 0xa36103b0);
		assert(p[5] == 0x9c7a1796);
		assert(p[6] == 0x61ff10b4);
		assert(p[7] == 0xad1500f2);
	} else {
		assert(p[0] == H[0]);
		assert(p[1] == H[1]);
		assert(p[2] == H[2]);
		assert(p[3] == H[3]);
		assert(p[4] == H[4]);
		assert(p[5] == H[5]);
		assert(p[6] == H[6]);
		assert(p[7] == H[7]);
	}

	/* = 448 bits */
	const char *message2 =
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	SHA256_compute_hash((const uint8_t *)message2, strlen(message2), H);
	assert(H[0] == 0x248d6a61);
	assert(H[1] == 0xd20638b8);
	assert(H[2] == 0xe5c02693);
	assert(H[3] == 0x0c3e6039);
	assert(H[4] == 0xa33ce459);
	assert(H[5] == 0x64ff2167);
	assert(H[6] == 0xf6ecedd4);
	assert(H[7] == 0x19db06c1);

	SHA256_get_digest(H, digest);
	if (is_little_endian()) {
		/* Convert H to little endian */
		assert(p[0] == 0x616a8d24);
		assert(p[1] == 0xb83806d2);
		assert(p[2] == 0x9326c0e5);
		assert(p[3] == 0x39603e0c);
		assert(p[4] == 0x59e43ca3);
		assert(p[5] == 0x6721ff64);
		assert(p[6] == 0xd4edecf6);
		assert(p[7] == 0xc106db19);
	} else {
		assert(p[0] == H[0]);
		assert(p[1] == H[1]);
		assert(p[2] == H[2]);
		assert(p[3] == H[3]);
		assert(p[4] == H[4]);
		assert(p[5] == H[5]);
		assert(p[6] == H[6]);
		assert(p[7] == H[7]);
	}

	/* > 448 bits */
	const char *message3 =
		"This is a test message that is definitely longer than sixty-four characters.";
	SHA256_compute_hash((const uint8_t *)message3, strlen(message3), H);
	assert(H[0] == 0x7904f52c);
	assert(H[1] == 0xc25631b9);
	assert(H[2] == 0x415a72c2);
	assert(H[3] == 0x6c1cf6ff);
	assert(H[4] == 0x3d356ffd);
	assert(H[5] == 0x8dc162d7);
	assert(H[6] == 0x644434c3);
	assert(H[7] == 0x029465c2);

	SHA256_get_digest(H, digest);
	if (is_little_endian()) {
		/* Convert H to little endian */
		assert(p[0] == 0x2cf50479);
		assert(p[1] == 0xb93156c2);
		assert(p[2] == 0xc2725a41);
		assert(p[3] == 0xfff61c6c);
		assert(p[4] == 0xfd6f353d);
		assert(p[5] == 0xd762c18d);
		assert(p[6] == 0xc3344464);
		assert(p[7] == 0xc2659402);
	} else {
		assert(p[0] == H[0]);
		assert(p[1] == H[1]);
		assert(p[2] == H[2]);
		assert(p[3] == H[3]);
		assert(p[4] == H[4]);
		assert(p[5] == H[5]);
		assert(p[6] == H[6]);
		assert(p[7] == H[7]);
	}

	/* Add more test cases... */
}

static void test_SHA1()
{
	uint32_t H[SHA1_WORD_COUNT];

	const char *message = "abc"; /* < 448 bits */
	SHA1_compute_hash((const uint8_t *)message, strlen(message), H);
	assert(H[0] == 0xa9993e36);
	assert(H[1] == 0x4706816a);
	assert(H[2] == 0xba3e2571);
	assert(H[3] == 0x7850c26c);
	assert(H[4] == 0x9cd0d89d);

	uint8_t digest[SHA1_DIGEST_SIZE / 8]; /* In bytes */
	SHA1_get_digest(H, digest);
	uint32_t *p = (uint32_t *)digest;
	if (is_little_endian()) { /* Most systems are little endian */
		/* Convert H to little endian */
		assert(p[0] == 0x363e99a9);
		assert(p[1] == 0x6a810647);
		assert(p[2] == 0x71253eba);
		assert(p[3] == 0x6cc25078);
		assert(p[4] == 0x9dd8d09c);
	} else {
		assert(p[0] == H[0]);
		assert(p[1] == H[1]);
		assert(p[2] == H[2]);
		assert(p[3] == H[3]);
		assert(p[4] == H[4]);
	}

	/* = 448 bits */
	const char *message2 =
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	SHA1_compute_hash((const uint8_t *)message2, strlen(message2), H);
	assert(H[0] == 0x84983e44);
	assert(H[1] == 0x1c3bd26e);
	assert(H[2] == 0xbaae4aa1);
	assert(H[3] == 0xf95129e5);
	assert(H[4] == 0xe54670f1);

	SHA1_get_digest(H, digest);
	if (is_little_endian()) {
		/* Convert H to little endian */
		assert(p[0] == 0x443e9884);
		assert(p[1] == 0x6ed23b1c);
		assert(p[2] == 0xa14aaeba);
		assert(p[3] == 0xe52951f9);
		assert(p[4] == 0xf17046e5);
	} else {
		assert(p[0] == H[0]);
		assert(p[1] == H[1]);
		assert(p[2] == H[2]);
		assert(p[3] == H[3]);
		assert(p[4] == H[4]);
	}

	/* > 448 bits */
	const char *message3 =
		"This is a test message that is definitely longer than sixty-four characters.";
	SHA1_compute_hash((const uint8_t *)message3, strlen(message3), H);
	assert(H[0] == 0x8a277b82);
	assert(H[1] == 0x3c087b6a);
	assert(H[2] == 0xbf7d731f);
	assert(H[3] == 0x5ec715ba);
	assert(H[4] == 0x3cf577ad);

	SHA1_get_digest(H, digest);
	if (is_little_endian()) {
		/* Convert H to little endian */
		assert(p[0] == 0x827b278a);
		assert(p[1] == 0x6a7b083c);
		assert(p[2] == 0x1f737dbf);
		assert(p[3] == 0xba15c75e);
		assert(p[4] == 0xad77f53c);
	} else {
		assert(p[0] == H[0]);
		assert(p[1] == H[1]);
		assert(p[2] == H[2]);
		assert(p[3] == H[3]);
		assert(p[4] == H[4]);
	}

	/* Add more test cases... */
}

int main(void)
{
	test_SHA256();
	test_SHA1();

	return 0;
}

#if defined(RESTORE_NDEBUG)
#define NDEBUG
#undef RESTORE_NDEBUG
#endif

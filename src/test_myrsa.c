/**
 * test_myrsa.c - Unit tests for myrsa functions.
 */

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "myrsa.h"
#include "mySHA.h"

void test_generate_RSA_keys()
{
	uint64_t prime1, prime2;
	uint64_t n, e, d;

	generate_RSA_keys(prime1 = 11, prime2 = 17, &n, &e, &d);
	assert(e == 19);
	assert(d == 59);
	assert(n == 187);
}

void test_RSA_trapdoor()
{
	uint64_t message, key, modulus;
	assert(RSA_trapdoor(message = 5, key = 3, modulus = 11) == 4);
	assert(RSA_trapdoor(987654321, 123456789, 1000000007) == 379110096);
}

/* Reference: 
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
 */
void test_SHA256()
{
	uint32_t H[SHA256_WORD_COUNT];

	char *message = "abc";
	SHA256_compute_hash(message, strlen(message), H);
	assert(H[0] == 0xba7816bf);
	assert(H[1] == 0x8f01cfea);
	assert(H[2] == 0x414140de);
	assert(H[3] == 0x5dae2223);
	assert(H[4] == 0xb00361a3);
	assert(H[5] == 0x96177a9c);
	assert(H[6] == 0xb410ff61);
	assert(H[7] == 0xf20015ad);

	char *message2 =
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	SHA256_compute_hash(message2, strlen(message2), H);
	assert(H[0] == 0x248d6a61);
	assert(H[1] == 0xd20638b8);
	assert(H[2] == 0xe5c02693);
	assert(H[3] == 0x0c3e6039);
	assert(H[4] == 0xa33ce459);
	assert(H[5] == 0x64ff2167);
	assert(H[6] == 0xf6ecedd4);
	assert(H[7] == 0x19db06c1);

	/* Add more test cases... */
}

void test_SHA()
{
	test_SHA256();

	/* Add more test cases... */
}

int main()
{
	test_generate_RSA_keys();
	test_RSA_trapdoor();
	test_SHA();

	/* Add calls to more test functions as needed... */

	return EXIT_SUCCESS;
}

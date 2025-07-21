/**
 * test_myrsa.c - Unit tests for myrsa functions.
 */

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "myrsa.h"
#include "mySHA.h"
#include "big_number.h"

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

/* Test RSA_trapdoor_big */
void test_RSA_trapdoor_big()
{
	bn message = bn_from_int(5);
	bn key = bn_from_int(3);
	bn modulus = bn_from_int(11);
	bn result = RSA_trapdoor_big(message, key, modulus);
	assert(result.size == 1);
	assert(result.data[0] == 4);

	message = bn_from_int(987654321);
	key = bn_from_int(123456789);
	modulus = bn_from_int(1000000007);
	result = RSA_trapdoor_big(message, key, modulus);
	assert(result.size == 4);
	assert(result.data[0] == 0x16);
	assert(result.data[1] == 0x98);
	assert(result.data[2] == 0xc2);
	assert(result.data[3] == 0xd0);

	/* Add more test cases... */
}

/* Reference: 
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
 */
void test_SHA256()
{
	uint32_t H[SHA256_WORD_COUNT];

	char *message = "abc"; /* < 448 bits */
	SHA256_compute_hash(message, strlen(message), H);
	assert(H[0] == 0xba7816bf);
	assert(H[1] == 0x8f01cfea);
	assert(H[2] == 0x414140de);
	assert(H[3] == 0x5dae2223);
	assert(H[4] == 0xb00361a3);
	assert(H[5] == 0x96177a9c);
	assert(H[6] == 0xb410ff61);
	assert(H[7] == 0xf20015ad);

	/* = 448 bits */
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

	/* > 448 bits */
	char *message3 =
		"This is a test message that is definitely longer than sixty-four characters.";
	SHA256_compute_hash(message3, strlen(message3), H);
	assert(H[0] == 0x7904f52c);
	assert(H[1] == 0xc25631b9);
	assert(H[2] == 0x415a72c2);
	assert(H[3] == 0x6c1cf6ff);
	assert(H[4] == 0x3d356ffd);
	assert(H[5] == 0x8dc162d7);
	assert(H[6] == 0x644434c3);
	assert(H[7] == 0x029465c2);

	/* Add more test cases... */
}

void test_SHA1()
{
	uint32_t H[SHA1_WORD_COUNT];

	char *message = "abc"; /* < 448 bits */
	SHA1_compute_hash(message, strlen(message), H);
	assert(H[0] == 0xa9993e36);
	assert(H[1] == 0x4706816a);
	assert(H[2] == 0xba3e2571);
	assert(H[3] == 0x7850c26c);
	assert(H[4] == 0x9cd0d89d);

	/* = 448 bits */
	char *message2 =
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	SHA1_compute_hash(message2, strlen(message2), H);
	assert(H[0] == 0x84983e44);
	assert(H[1] == 0x1c3bd26e);
	assert(H[2] == 0xbaae4aa1);
	assert(H[3] == 0xf95129e5);
	assert(H[4] == 0xe54670f1);

	/* > 448 bits */
	char *message3 =
		"This is a test message that is definitely longer than sixty-four characters.";
	SHA1_compute_hash(message3, strlen(message3), H);
	assert(H[0] == 0x8a277b82);
	assert(H[1] == 0x3c087b6a);
	assert(H[2] == 0xbf7d731f);
	assert(H[3] == 0x5ec715ba);
	assert(H[4] == 0x3cf577ad);

	/* Add more test cases... */
}

void test_SHA()
{
	test_SHA256();
	test_SHA1();

	/* Add more test cases... */
}

void test_big_number()
{
	/* Test bn_init */
	bn a;
	bn_init(&a);
	assert(a.size == 0);
	assert(a.data[0] == 0);

	/* Test bn_copy */
	bn b;
	bn_init(&b);
	bn_copy(&b, &a);
	assert(b.size == 0);
	assert(b.data[0] == 0);

	/* Test bn_from_int */
	bn c = bn_from_int(0x12345678);
	assert(c.size == 4);
	assert(c.data[0] == 0x12);
	assert(c.data[1] == 0x34);
	assert(c.data[2] == 0x56);
	assert(c.data[3] == 0x78);

	/* Test bn_to_string */
	char str[9];
	bn_to_string(&c, str, sizeof(str));
	assert(strcmp(str, "12345678") == 0);

	/* Test bn_is_not_zero */
	assert(bn_is_not_zero(&a) == 0);
	assert(bn_is_not_zero(&c) == 1);

	/* Test bn_is_odd */
	assert(bn_is_odd(&a) == 0);
	assert(bn_is_odd(&c) == 0);

	/* Test bn_add */
	bn d = bn_add(c, c);
	assert(d.size == 4);
	assert(d.data[0] == 0x24);
	assert(d.data[1] == 0x68);
	assert(d.data[2] == 0xac);
	assert(d.data[3] == 0xf0);

	/* Test bn_inc */
	bn e;
	bn_init(&e);
	bn_inc(&e);
	assert(e.size == 1);
	assert(e.data[0] == 1);

	/* Test bn_sub */
	bn f = bn_sub(c, c);
	assert(f.size == c.size);
	assert(f.data[0] == 0);
	assert(f.data[c.size - 1] == 0);

	/* Test bn_mul */
	bn g = bn_mul(c, c);
	assert(g.size == 8);
	assert(g.data[0] == 0x01);
	assert(g.data[1] == 0x4b);
	assert(g.data[2] == 0x66);
	assert(g.data[3] == 0xdc);
	assert(g.data[4] == 0x1d);
	assert(g.data[5] == 0xf4);
	assert(g.data[6] == 0xd8);
	assert(g.data[7] == 0x40);

	/* Test bn_cmp */
	assert(bn_cmp(&a, &b) == 0);
	assert(bn_cmp(&a, &c) == -1);
	assert(bn_cmp(&c, &a) == 1);

	/* Test bn_left_shift */
	bn h;
	bn_init(&h);
	h.data[0] = 0x01;
	h.data[1] = 0x80;
	h.size = 2;
	bn_left_shift(&h);
	assert(h.size == 2);
	assert(h.data[0] == 0x03);
	assert(h.data[1] == 0x00);

	/* Test bn_right_shift */
	bn p;
	bn_init(&p);
	p.data[0] = 0x03;
	p.data[1] = 0x00;
	p.size = 2;
	bn_right_shift(&p);
	assert(p.size == 2);
	assert(p.data[0] == 0x01);
	assert(p.data[1] == 0x80);

	/* Test bn_mod */
	bn i = bn_from_int(0x1234567);
	bn j = bn_from_int(0xfff);
	bn k = bn_mod(i, j);
	assert(k.size == j.size);
	assert(k.data[0] == 0x07);
	assert(k.data[1] == 0x9c);

	/* c == c */
	bn l = bn_mod(c, c);
	assert(l.size == c.size);
	assert(l.data[0] == 0);
	assert(l.data[l.size - 1] == 0);

	/* g > c */
	bn m = bn_mod(g, c);
	assert(m.size == c.size);
	assert(m.data[0] == 0x00);
	assert(m.data[m.size - 1] == 0x00);

	/* c < d */
	bn n = bn_mod(c, d);
	assert(n.size == d.size);
	assert(n.data[0] == 0x12);
	assert(n.data[n.size - 1] == 0x78);
}

int main()
{
	test_generate_RSA_keys();
	test_RSA_trapdoor();
	test_SHA();
	test_big_number();
	test_RSA_trapdoor_big();

	/* Add calls to more test functions as needed... */

	return EXIT_SUCCESS;
}

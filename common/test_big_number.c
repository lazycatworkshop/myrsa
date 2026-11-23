/* test_big_number.c */

/* assert() is required */
#if defined(NDEBUG)
#define RESTORE_ASSERT
#undef NDEBUG
#endif

#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include "big_number.h"

static void test_bn_init()
{
	bn a;
	bn_init(&a);
	assert(a.size == 0);
	for (size_t i = 0; i < MAX_DATA_SIZE; i++) {
		assert(a.data[i] == 0);
	}
}

static void test_bn_copy()
{
	bn a, b;
	bn_init(&a);
	a.size = 3;
	a.data[0] = 1;
	a.data[1] = 2;
	a.data[2] = 3;

	bn_copy(&b, &a);
	assert(b.size == a.size);
	for (size_t i = 0; i < a.size; i++) {
		assert(b.data[i] == a.data[i]);
	}

	/* Big number tests */
	bn_init(&a);
	bn_init(&b);
	a.size = 5;
	a.data[0] = 10;
	a.data[1] = 20;
	a.data[2] = 30;
	a.data[3] = 40;
	a.data[4] = 50;
	bn_copy(&b, &a);
	assert(b.size == a.size);
	for (size_t i = 0; i < a.size; i++) {
		assert(b.data[i] == a.data[i]);
	}

	bn_init(&a);
	bn_init(&b);
	a.size = 10; /* Empty big number */
	for (size_t i = 0; i < a.size; i++) {
		a.data[i] = (uint8_t)(i + 1);
	}
	bn_copy(&b, &a);
	assert(b.size == a.size);
	for (size_t i = 0; i < a.size; i++) {
		assert(b.data[i] == a.data[i]);
	}
}

static void test_bn_from_int()
{
	bn a = bn_from_int(0);
	assert(a.size == 1);
	assert(a.data[0] == 0);

	a = bn_from_int(123456789);
	assert(a.size == 4);
	assert(a.data[0] == 0x07);
	assert(a.data[1] == 0x5b);
	assert(a.data[2] == 0xcd);
	assert(a.data[3] == 0x15);
}

static void test_bn_to_string()
{
	bn a = bn_from_int(123456789);
	char str[8 * 2 + 1]; /* 8 bytes + null terminator */
	;
	bn_to_string(&a, str, sizeof(str));
	assert(strcmp(str, "075BCD15") == 0);

	a = bn_from_int(-1);
	bn_to_string(&a, str, sizeof(str));
	assert(strcmp(str, "FFFFFFFFFFFFFFFF") == 0);
}

static void test_bn_is_zero()
{
	bn a = bn_from_int(0);
	assert(bn_is_zero(&a));

	a = bn_from_int(1);
	assert(!bn_is_zero(&a));

	a = bn_from_int(65536);
	assert(!bn_is_zero(&a));
}

static void test_bn_is_odd()
{
	bn a = bn_from_int(0);
	assert(!bn_is_odd(&a));

	a = bn_from_int(1);
	assert(bn_is_odd(&a));

	a = bn_from_int(65535);
	assert(bn_is_odd(&a));

	a = bn_from_int(65536);
	assert(!bn_is_odd(&a));
}

static void test_bn_cmp()
{
	bn a = bn_from_int(0);
	bn b = bn_from_int(0);
	assert(bn_cmp(&a, &b) == 0);

	a = bn_from_int(65536);
	b = bn_from_int(65535);
	assert(bn_cmp(&a, &b) == 1);

	a = bn_from_int(LONG_MAX - 1);
	b = bn_from_int(LONG_MAX);
	assert(bn_cmp(&a, &b) == -1);
}

static void test_bn_left_shift()
{
	bn a = bn_from_int(1);
	bn_left_shift(&a);
	assert(a.size == 1);
	assert(a.data[0] = 2);

	a.data[0] = 0x80;
	a.size = 1;
	bn_left_shift(&a); /* 0x80 << 1 = 0x100 */
	assert(a.size == 1);
	assert(a.data[0] == 0);

	a = bn_from_int(65535); /* 0xffff */
	bn_left_shift(&a); /* 0x1fffe */
	assert(a.size == 2);
	assert(a.data[0] == 0xff);
	assert(a.data[1] == 0xfe);
}

static void test_bn_right_shift()
{
	bn a = bn_from_int(2);
	bn_right_shift(&a);
	assert(a.size == 1);
	assert(a.data[0] == 1);

	a = bn_from_int(256); /* 0x100 */
	bn_right_shift(&a); /* 0x100 >> 1 = 0x80 */
	assert(a.size == 2);
	assert(a.data[1] == 0x80);

	a = bn_from_int(65536); /* 0x10000 */
	bn_right_shift(&a); /* 0x10000 >> 1 = 0x08000 */
	assert(a.size == 3); /* No trimming */
	assert(a.data[0] == 0);
	assert(a.data[1] == 0x80);
	assert(a.data[2] == 0);
}

static void test_bn_inc()
{
	bn a;
	bn_init(&a);
	bn_inc(&a);
	assert(a.size == 1);
	assert(a.data[0] == 1);
	bn_inc(&a);
	assert(a.size == 1);
	assert(a.data[0] == 2);

	a = bn_from_int(255); /* 0xff */
	bn_inc(&a); /* 0x100 */
	assert(a.size == 2);
	assert(a.data[0] == 1);
	assert(a.data[1] == 0);
	bn_inc(&a); /* 0x100 + 1 = 0x101 */
	assert(a.size == 2);
	assert(a.data[0] == 1);
	assert(a.data[1] == 1);

	a = bn_from_int(65535); /* 0xffff */
	bn_inc(&a); /* 65535 + 1 = 65536 = 0x10000 */
	assert(a.size == 3);
	assert(a.data[0] == 1);
	assert(a.data[1] == 0);
	assert(a.data[2] == 0);
	bn_inc(&a); /* 65536 + 1 = 65537 = 0x10001 */
	assert(a.size == 3);
	assert(a.data[0] == 1);
	assert(a.data[1] == 0);
	assert(a.data[2] == 1);
}

static void test_bn_add()
{
	bn a = bn_from_int(1);
	bn b = bn_from_int(2);
	bn c = bn_add(&a, &b);
	assert(c.size == 1);
	assert(c.data[0] == 3);

	a = bn_from_int(255); /* 0xff */
	b = bn_from_int(1); /* 0x01 */
	c = bn_add(&a, &b); /* 0xff + 0x01 = 0x100 */
	assert(c.size == 2);
	assert(c.data[0] == 1);
	assert(c.data[1] == 0);

	a = bn_from_int(65535); /* 0xffff */
	b = bn_from_int(1); /* 0x0001 */
	c = bn_add(&a, &b); /* 0xffff + 0x0001 = 0x10000 */
	assert(c.size == 3);
	assert(c.data[0] == 1);
	assert(c.data[1] == 0);
	assert(c.data[2] == 0);
}

static void test_bn_sub()
{
	bn a = bn_from_int(5);
	bn b = bn_from_int(3);

	bn c = bn_sub(&a, &a);
	assert(c.size == a.size); /* No trimming */
	assert(c.data[0] == 0);

	c = bn_sub(&a, &b);
	assert(c.size == 1);
	assert(c.data[0] == 2);

	a = bn_from_int(256); /* 0x100 */
	b = bn_from_int(1); /* 0x001 */
	c = bn_sub(&a, &b); /* 0x100 - 0x001 = 0x0ff */
	assert(c.size == 2);
	assert(c.data[0] == 0);
	assert(c.data[1] == 0xff);

	a = bn_from_int(65536); /* 0x10000 */
	b = bn_from_int(1); /* 0x00001 */
	c = bn_sub(&a, &b); /* 0x10000 - 0x00001 = 0x0ffff */
	assert(c.size == 3);
	assert(c.data[0] == 0);
	assert(c.data[1] == 0xff);
	assert(c.data[2] == 0xff);
}

static void test_bn_mul()
{
	bn a = bn_from_int(2);
	bn b = bn_from_int(3);
	bn c = bn_mul(a, b);
	assert(c.size == 1);
	assert(c.data[0] == 6);

	a = bn_from_int(255); /* 0xff */
	b = bn_from_int(2); /* 0x02 */
	c = bn_mul(a, b); /* 0xff * 0x02 = 0x1fe */
	assert(c.size == 2);
	assert(c.data[0] == 1);
	assert(c.data[1] == 0xfe);

	a = bn_from_int(65535); /* 0xffff */
	b = bn_from_int(2); /* 0x0002 */
	c = bn_mul(a, b); /* 0xffff * 0x0002 = 0x1fffe */
	assert(c.size == 3);
	assert(c.data[0] == 1);
	assert(c.data[1] == 0xff);
	assert(c.data[2] == 0xfe);
}

static void test_bn_mod()
{
	/* a < b */
	bn a = bn_from_int(3);
	bn b = bn_from_int(256);
	bn c = bn_mod(a, b);
	assert(c.size == b.size); /* Match the size of the divisor */
	assert(c.data[0] == 0);
	assert(c.data[1] == 3);

	/* a == b */
	a = bn_from_int(256);
	b = bn_from_int(256);
	c = bn_mod(a, b);
	assert(c.size == 2);
	assert(bn_is_zero(&c));

	/* a > b */
	a = bn_from_int(10);
	b = bn_from_int(3);
	c = bn_mod(a, b);
	assert(c.size == 1);
	assert(c.data[0] == 1);

	a = bn_from_int(255); /* 0xff */
	b = bn_from_int(16); /* 0x10 */
	c = bn_mod(a, b); /* 0xff % 0x10 = 0x0f */
	assert(c.size == 1);
	assert(c.data[0] == 0xf);

	/* Result is zero */
	a = bn_from_int(65536); /* 0xffff */
	b = bn_from_int(256); /* 0x0100 */
	c = bn_mod(a, b); /* 0xffff % 0x0100 = 0x0000 */
	assert(c.size == b.size);
	assert(bn_is_zero(&c));

	a = bn_from_int(65535); /* 0xffff */
	b = bn_from_int(256); /* 0x0100 */
	c = bn_mod(a, b); /* 0xffff % 0x0100 = 0x00ff */
	assert(c.size == b.size);
	assert(c.data[0] == 0);
	assert(c.data[1] == 0xff);
}

int main()
{
	test_bn_init();
	test_bn_copy();
	test_bn_from_int();
	test_bn_to_string();
	test_bn_is_zero();
	test_bn_is_odd();
	test_bn_cmp();
	test_bn_left_shift();
	test_bn_right_shift();
	test_bn_inc();
	test_bn_add();
	test_bn_sub();
	test_bn_mul();
	test_bn_mod();
	/* test_bn_div(); */

	return 0;
}

#if defined(RESTORE_ASSERT)
#undef RESTORE_ASSERT
#define NDEBUG
#endif

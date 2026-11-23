/* test_asn1.c - Unit tests for ASN.1 helper functions. */

#if defined(NDEBUG)
#define RESTORE_ASSERT
#undef NDEBUG
#endif

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "asn1.h"
#include "memfp.h"

static void test_identifier_octet(void)
{
	uint8_t sequence = 0x30;
	uint8_t context_specific = 0x82;

	assert(asn1_get_tag(sequence) == ASN1_TAG_SEQUENCE);
	assert(asn1_is_constructed(sequence));
	assert(asn1_get_tag(context_specific) == ASN1_TAG_CONTEXT_SPECIFIC_2);
	assert(!asn1_is_constructed(context_specific));
}

static void test_length_octet(void)
{
	struct memfp mp;

	const uint8_t short_length[] = { 0x7f };
	const uint8_t long_length[] = { 0x82, 0x01, 0x00 };
	const uint8_t indefinite_length[] = { 0x80 };

	assert(asn1_is_short_form(short_length[0]));
	assert(asn1_get_length_bytes(short_length[0]) == 0);
	memfp_open(&mp, short_length, sizeof(short_length));
	assert(asn1_get_length(&mp) == 127);
	memfp_close(&mp);

	assert(asn1_is_long_form(long_length[0]));
	assert(asn1_get_length_bytes(long_length[0]) == 2);
	memfp_open(&mp, long_length, sizeof(long_length));
	assert(asn1_get_length(&mp) == 256);
	memfp_close(&mp);

	assert(asn1_is_indefinite_form(indefinite_length[0]));
	assert(asn1_get_length_bytes(indefinite_length[0]) == 0);
	memfp_open(&mp, indefinite_length, sizeof(indefinite_length));
	assert(asn1_get_length(&mp) == ASN1_INDEFINITE_LENGTH);
	memfp_close(&mp);
}

static void test_oid(void)
{
	const uint8_t encoded_oid[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7,
					0x0d, 0x01, 0x01, 0x01 };
	const uint32_t expected_oid[] = { 1, 2, 840, 113549, 1, 1, 1 };
	uint32_t oid[7] = { 0 };
	int oid_length = 7;

	assert(asn1_get_oid(encoded_oid, sizeof(encoded_oid), oid,
			    &oid_length) == 0);
	assert(oid_length == 7);
	for (int i = 0; i < oid_length; i++)
		assert(oid[i] == expected_oid[i]);

	oid_length = 6; /* too small */
	assert(asn1_get_oid(encoded_oid, sizeof(encoded_oid), oid,
			    &oid_length) != 0);
}

static void test_boolean(void)
{
	assert(asn1_is_true(ASN1_BOOLEAN_TRUE));
	assert(!asn1_is_true(ASN1_BOOLEAN_FALSE));
}

int main(void)
{
	test_identifier_octet();
	test_length_octet();
	test_oid();
	test_boolean();

	return EXIT_SUCCESS;
}

#if defined(RESTORE_ASSERT)
#undef RESTORE_ASSERT
#define NDEBUG
#endif

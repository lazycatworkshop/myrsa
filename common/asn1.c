/* asn1.c - Implementation file for ASN.1 handling */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "asn1.h"
#include "oid.h"
#include "memfp.h"

/** 
 * asn1_get_oid - Decode an ASN.1 Object Identifier (OID) from its DER encoding.
 *
 * @param octets The DER-encoded OID octets.
 * @param length The length of the DER-encoded OID.
 * @param oid The array to store the decoded OID components.
 * @param oid_length In: capacity of oid[]. Out: number of decoded components.
 * @return 0 on success, -1 if oid[] is too small.
 */
int asn1_get_oid(const uint8_t octets[], int length, uint32_t oid[],
		 int *oid_length)
{
	int i = 0; /* index to the octets array */
	uint32_t value = 0;
	int j = 0; /* index to the oid array */
	int max = *oid_length;

	/* The first byte = X * 40 + Y */
	if (length > 0) {
		if (max < 2)
			return -1;
		oid[j++] = octets[i] / 40;
		oid[j++] = octets[i] % 40;
		i++;
	}

	while (i < length) {
		uint8_t c = octets[i++];
		value = (value << 7) | (c & 0x7F); /* Base 128 encoding */
		if ((c & 0x80) == 0) { /* End of this subidentifier */
			if (j >= max)
				return -1;
			oid[j++] = value;
			value = 0;
		}
	}
	*oid_length = j;
	return 0;
}

int asn1_get_length(struct memfp *mp)
{
	int length_bytes;
	int length = mgetc(mp); /* if short form */
	if (!asn1_is_indefinite_form(length)) {
		if (asn1_is_long_form(length)) {
			length_bytes = asn1_get_length_bytes(length);
			length = 0;
			for (int i = 0; i < length_bytes; i++) {
				length = (length << 8) | mgetc(mp);
			}
		}
	} else
		length = ASN1_INDEFINITE_LENGTH;

	return length;
}

/* asn1_walk_thru - Find the actual length of an ASN.1 syntax 
 * @pos: Pointer to the buffer
 * @length: Length of the buffer
 * 
 * This function will walk through the ASN.1 syntax and return the actual
 * length of the ASN.1 syntax.
 * 
 * Return: The actual length of the ASN.1 syntax
 */
static int asn1_walk_thru(struct memfp *mp, int length)
{
	int ret = 0;

	while (length > 0) {
		int len = 0;
		int offset1, offset2 = 0;
		offset1 = mtell(mp);

		/* Tag */
		int c = mgetc(mp);
		int tag = asn1_get_tag(c);

		/* Length */
		len = asn1_get_length(mp);

		if (tag == ASN1_TAG_EOC) {
			length = 0; /* Complete current level */
			/*ret += 2; */ /* Do not include EOC in the value component */
			continue; /* Back to the upper level */
		}

		/* Content */
		if (len == ASN1_INDEFINITE_LENGTH)
			len = asn1_walk_thru(mp, len);
		else
			mseek(mp, len, SEEK_CUR);

		offset2 = mtell(mp);
		int len1 = offset2 - offset1;
		length -= len1;
		ret += len1;
	}

	return ret;
}

/**
 * asn1_load - Load an ASN.1 object from a buffer.
 *
 * @param asn1 The ASN.1 object to populate.
 * @param asn1_buf The buffer containing the ASN.1 encoded data.
 * @return 0 on success, non-zero on failure.
 */
int asn1_load(struct memfp *mp, ASN1Object *asn1)
{
	asn1->tag = mgetc(mp);
	asn1->length = asn1_get_length(mp);
	asn1->value = mp->pos;
	if (asn1->length == ASN1_INDEFINITE_LENGTH)
		asn1->length = asn1_walk_thru(mp, asn1->length);
	else
		mseek(mp, asn1->length, SEEK_CUR);

	return 0;
}

int asn1_load_tag(struct memfp *mp, ASN1Object *asn1, uint8_t tag)
{
	int c = mpeekc(mp);
	if (asn1_get_tag(c) != tag) {
		return -1;
	}

	if (asn1_load(mp, asn1) != 0) {
		return -1;
	}

	return 0;
}

int asn1_get_oid_type(const ASN1Object *asn1)
{
	uint32_t oid[OID_MAX_LEN];
	int oid_length = OID_MAX_LEN;

	if (asn1_get_oid(asn1->value, asn1->length, oid, &oid_length) != 0) {
		fprintf(stderr, "Error: Failed to get OID\n");
		exit(EXIT_FAILURE);
	}
	return lookup_oid(oid, oid_length);
}

void asn1_print_oid(const ASN1Object *asn1)
{
	static uint32_t oid[OID_MAX_LEN];
	int oid_length = OID_MAX_LEN;

	if (asn1_get_tag(asn1->tag) != ASN1_TAG_OBJECT_IDENTIFIER) {
		fprintf(stderr, "Error: Not an OID\n");
		return;
	}

	if (asn1_get_oid(asn1->value, asn1->length, oid, &oid_length) != 0) {
		fprintf(stderr, "Error: Failed to get OID\n");
		return;
	}
	int oid_type = lookup_oid(oid, oid_length);
	if (print_oid_desc(oid_type) != 0) {
		print_oid(oid, oid_length);
	}
}

void asn1_print_printable_string(const ASN1Object *obj)
{
	uint8_t tag = asn1_get_tag(obj->tag);

	char s[ASN1_MAX_STRING_LENGTH];
	switch (tag) {
	case ASN1_TAG_PRINTABLE_STRING:
	case ASN1_TAG_UTF8_STRING:
	case ASN1_TAG_IA5_STRING:
	case ASN1_TAG_T61_STRING:
	case ASN1_TAG_VISIBLE_STRING:
		memcpy(s, obj->value, obj->length);
		s[obj->length] = '\0';
		printf("%s", s);
		break;
	default:
		fprintf(stderr, "Error: Unsupported string type\n");
		break;
	}
}

void asn1_print_time_string(const ASN1Object *obj)
{
	uint8_t tag = asn1_get_tag(obj->tag);

	char s[ASN1_MAX_STRING_LENGTH];
	switch (tag) {
	case ASN1_TAG_UTC:
	case ASN1_TAG_GENERALIZED_TIME:
		memcpy(s, obj->value, obj->length);
		s[obj->length] = '\0';
		printf("%s", s);
		break;
	default:
		fprintf(stderr, "Error: Unsupported time string type\n");
		break;
	}
}

static void asn1_dump8(const uint8_t *buf, size_t len)
{
	/* 16 bytes / row, blank between two bytes */
	for (size_t i = 0; i < len; i++) {
		printf("%02X", buf[i]);
		if ((i + 1) % 16 == 0) {
			printf("\n");
		} else {
			printf(" ");
		}
	}
}

void asn1_print_bit_string(const ASN1Object *obj)
{
	if (asn1_get_tag(obj->tag) != ASN1_TAG_BIT_STRING) {
		fprintf(stderr, "Error: Not a valid bit string\n");
		exit(EXIT_FAILURE);
	}

	/* Skip the unused bits byte */
	const uint8_t *p = obj->value;
	size_t l = obj->length;
	if (l > 0) {
		++p;
		--l;
	}
	asn1_dump8(p, l);
}

void asn1_print_integer(const ASN1Object *obj)
{
	if (asn1_get_tag(obj->tag) != ASN1_TAG_INTEGER) {
		fprintf(stderr, "Error: Not a valid integer\n");
		exit(EXIT_FAILURE);
	}

	const uint8_t *p = obj->value;
	size_t l = obj->length;
	if (l > 1 && (p[0] == 0x00 && (p[1] & 0x80) == 0x80)) {
		++p; /* Skip leading 0x00 byte for positive integer */
		--l;
	}
	if (l > 4) {
		/* Treat as big number */
		asn1_dump8(p, l);
	} else {
		uint32_t value = 0;
		for (size_t i = 0; i < l; i++) {
			value = (value << 8) | p[i];
		}
		printf("%u", value);
	}
}

void asn1_print_octet_string(const ASN1Object *obj)
{
	if (asn1_get_tag(obj->tag) != ASN1_TAG_OCTET_STRING) {
		fprintf(stderr, "Error: Not a valid octet string\n");
		exit(EXIT_FAILURE);
	}

	asn1_dump8(obj->value, obj->length);
}

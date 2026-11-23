/** oid.c - Common functions for Object Identifiers */
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include "oid.h"

static int compare_oids(const uint32_t oid1[], uint32_t oid1_len,
			const uint32_t oid2[], uint32_t oid2_len)
{
	if (oid1_len != oid2_len)
		return 0;
	for (uint32_t i = 0; i < oid1_len; i++) {
		if (oid1[i] != oid2[i])
			return 0;
	}
	return 1;
}

int lookup_oid(const uint32_t oid[], uint32_t oid_len)
{
	if (oid == NULL || oid_len == 0)
		return OID_TYPES_UNKNOWN;
	for (int i = 0; i < OID_TYPES_COUNT; i++) {
		if (compare_oids(oid, oid_len, oid_database[i].oid,
				 oid_database[i].oid_len))
			return i;
	}
	return OID_TYPES_UNKNOWN;
}

void print_oid(const uint32_t oid[], uint32_t oid_len)
{
	for (uint32_t i = 0; i < oid_len; i++) {
		if (i > 0)
			printf(".");
		printf("%" PRIu32, oid[i]);
	}
}

int print_oid_desc(int oid_type)
{
	if (oid_type != OID_TYPES_UNKNOWN) {
		printf("%s", oid_database[oid_type].desc);
		return 0;
	}
	return -1;
}

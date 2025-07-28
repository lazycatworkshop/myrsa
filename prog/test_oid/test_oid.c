/** test_oid.c - Test suite for Object ID functions */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "oid.h"

typedef struct {
	uint32_t oid_len;
	uint32_t oid_value[128];
	char *description;
} OID;
extern OID oid_database[];

int main()
{
	{
		/* First */
		uint8_t asn1_oid_value[] = { 0x2A };
		uint8_t asn1_oid_len = sizeof(asn1_oid_value);
		uint32_t oid_value[128];
		uint32_t oid_len;

		decode_asn1_oid(asn1_oid_value, asn1_oid_len, oid_value,
				&oid_len);
		int index = asn1_lookup_oid(oid_value, oid_len);
		assert(index == OID_TYPE_ISO);
		assert(strcmp("iso", oid_database[index].description) == 0);
	}

	{
		/* Middle */
		uint8_t asn1_oid_value[] = { 0x2B, 0x06, 0x01, 0x05,
					     0x05, 0x07, 0x01, 0x01 };
		uint8_t asn1_oid_len = sizeof(asn1_oid_value);
		uint32_t oid_value[128];
		uint32_t oid_len;

		decode_asn1_oid(asn1_oid_value, asn1_oid_len, oid_value,
				&oid_len);
		int index = asn1_lookup_oid(oid_value, oid_len);
		assert(index == OID_TYPE_AUTHORITY_INFO_ACCESS);
		assert(strcmp("id-pe-authorityInfoAccess",
			      oid_database[index].description) == 0);
	}

	{
		/* Last */
		uint8_t asn1_oid_value[] = {
			0x67, 0x81, 0x0C, 0x01, 0x02, 0x01
		};
		uint8_t asn1_oid_len = sizeof(asn1_oid_value);
		uint32_t oid_value[128];
		uint32_t oid_len;

		decode_asn1_oid(asn1_oid_value, asn1_oid_len, oid_value,
				&oid_len);
		int index = asn1_lookup_oid(oid_value, oid_len);
		assert(index == OID_TYPE_DOMAIN_VALID);
		assert(strcmp("domain-validated",
			      oid_database[index].description) == 0);
	}

	return 0;
}
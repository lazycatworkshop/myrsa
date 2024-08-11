/** asn1parse.c - This is a program that takes in a DER file and show the
 * content in ASN.1 syntax.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>

enum {
	VERBOSE_LEVEL_NONE,
	VERBOSE_LEVEL_INFO,
	VERBOSE_LEVEL_DEBUG
} verbose_level = VERBOSE_LEVEL_NONE;

enum OID_TYPE {
	OID_TYPE_RSA,
	OID_TYPE_RSA_ENCRYPTION,
	OID_TYPE_SHA256_WITH_RSA_ENCRYPTION,
	/* Add more OIDs as needed */

	OID_TYPE_UNKNOWN = 0xff
};

int asn1_print_tag(uint8_t tag);
int asn1_lookup_oid(uint8_t asn1_oid_value[], uint8_t asn1_oid_len);
void print_oid(int oid_type);

int main(int argc, char *argv[])
{
	int ret = EXIT_SUCCESS;
	int opt;
	char *filename = NULL;
	FILE *fp = NULL;
	while ((opt = getopt(argc, argv, "f:v")) != -1) {
		switch (opt) {
		case 'f':
			filename = optarg;
			break;
		case 'v':
			verbose_level++;
			break;
		default:
			fprintf(stderr, "Usage: %s -f filename [-v]\n",
				argv[0]);
			ret = EXIT_FAILURE;
			goto out;
		}
	}

	if (filename == NULL) {
		fprintf(stderr, "Usage: %s -f filename [-v]\n", argv[0]);
		ret = EXIT_FAILURE;
		goto out;
	}

	fp = fopen(filename, "r");
	if (fp == NULL) {
		fprintf(stderr, "Error: Cannot open file %s\n", filename);
		ret = EXIT_FAILURE;
		goto out;
	}

	fseek(fp, 0, SEEK_END);
	long fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	if (!fsize) {
		fprintf(stderr, "Error: File is empty\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	int c = getc(fp);
	if (c == '-') { /* Encapsulate Boundary in PEM */
		fprintf(stderr, "Error: File is in PEM format\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	fseek(fp, 0, SEEK_SET);

	if (verbose_level >= VERBOSE_LEVEL_DEBUG) {
		printf("File size: %ld\n", fsize);
		int j = 0;
		while ((c = getc(fp)) != EOF) {
			if (j % 16 == 0)
				printf("%04lx: ", ftell(fp) - 1);
			printf("%02x ", c);
			if (++j % 16 == 0)
				printf("\n");
		}
		printf("\n");
		fseek(fp, 0, SEEK_SET);
	}

	enum ASN1_TAG {
		ASN1_TAG_INTEGER = 0x02,
		ASN1_TAG_BIT_STRING = 0x03,
		ASN1_TAG_OCTET_STRING = 0x04,
		ASN1_TAG_NULL = 0x05,
		ASN1_TAG_OBJECT_IDENTIFIER = 0x06,
		ASN1_TAG_SEQUENCE = 0x30,
		ASN1_TAG_UNKNOWN = 0xff
	};

	const uint8_t ans1_tag_constructive = 0x20;

	/* Parse the ASN.1 content */
	uint8_t is_construct = 0;
	while ((c = getc(fp)) != EOF) {
		printf("%04lx: ", ftell(fp) - 1);

		/*  Identifier octets */
		uint8_t tag = c;
		if (asn1_print_tag(tag) < 0) {
			fprintf(stderr, "Error: Unknown tag 0x%02x\n", tag);
			ret = EXIT_FAILURE;
			goto out;
		}

		/* Length octets */
		int length = getc(fp);
		if (length & 0x80) {
			uint8_t length_bytes = length & 0x7f;
			length = 0;
			for (int i = 0; i < length_bytes; i++) {
				length = (length << 8) | getc(fp);
			}
		}
		printf("\tL = %d\n", length);
		if (!length)
			continue;

		/* Content octets */
		if (tag & ans1_tag_constructive) { /* Constructive */
			continue;
		}

		if (tag == ASN1_TAG_OBJECT_IDENTIFIER) {
			uint8_t oid_value[128];
			for (int i = 0; i < length; i++) {
				oid_value[i] = getc(fp);
			}
			int oid_type = asn1_lookup_oid(oid_value, length);
			if (oid_type == OID_TYPE_UNKNOWN) {
				printf("Unknown OID\n");
			} else {
				switch (oid_type) {
				case OID_TYPE_RSA_ENCRYPTION:
					is_construct = 1;
					break;
				default:
					is_construct = 0;
					break;
				}
				print_oid(oid_type);
			}
			continue;
		}

		if (tag == ASN1_TAG_BIT_STRING) {
			uint8_t unused_bits = getc(fp);
			printf("%04lx: ", ftell(fp) - 1);
			printf("Unused bits: %d\n", unused_bits);
			length--;

			if (is_construct)
				continue; /* Make it constructive */
		}

		if (tag == ASN1_TAG_OCTET_STRING) {
			if (is_construct)
				continue; /* Make it constructive */
		}

		/* General primitives */
		for (int i = 0; i < length; i++) {
			c = getc(fp);
			if (i % 16 == 0)
				printf("%04lx: ", ftell(fp) - 1);
			printf("%02x ", c);
			if (i % 16 == 15)
				printf("\n");
		}
		if (length % 16)
			printf("\n");
	}

out: /* Clean up */

	if (fp)
		fclose(fp);

	return ret;
}

int asn1_print_tag(uint8_t tag)
{
	int ret = 0;

	if (verbose_level >= VERBOSE_LEVEL_INFO)
		printf("Tag: %02x\t", tag);
	switch (tag) {
	case 0x02:
		printf("INTEGER\t");
		break;
	case 0x03:
		printf("BIT STRING\t");
		break;
	case 0x04:
		printf("OCTET STRING\t");
		break;
	case 0x05:
		printf("NULL\t");
		break;
	case 0x06:
		printf("OBJECT IDENTIFIER\t");
		break;
	case 0x30:
		printf("SEQUENCE\t");
		break;
	default:
		ret = -1;
		break;
	}

	return ret;
}

typedef struct {
	uint32_t oid_len;
	uint32_t oid_value[128];
	char *description;
} OID;

OID oid_database[] = {
	{ .oid_len = 4,
	  .oid_value = { 1, 2, 840, 113549 },
	  .description = "RSA" },
	{ 7, { 1, 2, 840, 113549, 1, 1, 1 }, "rsaEncryption" },
	{ 7, { 1, 2, 840, 113549, 1, 1, 11 }, "sha256withRSAEncryption" }
	/* Add more OIDs as needed */
};

/**
 * decode_asn1_oid - Decodes an ASN.1 encoded OID
 * @asn1_oid_value: The ASN.1 encoded OID value
 * @asn1_oid_len: The length of the ASN.1 encoded OID value
 * @oid_value: The array to store the decoded OID values (Output)
 * @oid_len: Pointer to a variable to store the length of the decoded OID (Output)
 *
 * This function takes an ASN.1 encoded OID and decodes it into its numerical
 * components.
 */
void decode_asn1_oid(uint8_t asn1_oid_value[], uint8_t asn1_oid_len,
		     uint32_t oid_value[], uint32_t *oid_len)
{
	uint32_t value = 0;
	uint32_t i = 0;
	for (int j = 0; j < asn1_oid_len; j++) {
		uint8_t c = asn1_oid_value[j];
		value = (value << 7) | (c & 0x7f);
		if (!(c & 0x80)) {
			if (i == 0) {
				oid_value[i++] = value / 40;
				oid_value[i++] = value % 40;
			} else {
				oid_value[i++] = value;
			}
			value = 0;
		}
	}
	*oid_len = i;
}

/**
 * asn1_lookup_oid - Looks up an OID in the OID database
 * @asn1_oid_value: The ASN.1 encoded OID value
 * @asn1_oid_len: The length of the ASN.1 encoded OID value
 *
 * This function decodes an ASN.1 encoded OID and searches for it in the
 * predefined OID database. The components of an OID are up to 32 bits long.
 *
 * Return: The index of the OID in the OID database if found, otherwise -1.
 */
int asn1_lookup_oid(uint8_t asn1_oid_value[], uint8_t asn1_oid_len)
{
	uint32_t oid_len = 0;
	uint32_t oid_value[128];

	decode_asn1_oid(asn1_oid_value, asn1_oid_len, oid_value, &oid_len);

	for (int i = 0; i < sizeof(oid_database) / sizeof(OID); i++) {
		if (oid_database[i].oid_len == oid_len) {
			if (memcmp(oid_database[i].oid_value, oid_value,
				   oid_len * sizeof(uint32_t)) == 0)
				return i;
		}
	}
	return OID_TYPE_UNKNOWN;
}

void print_oid(int oid_type)
{
	printf("OID: ");
	for (int i = 0; i < oid_database[oid_type].oid_len; i++)
		printf("%d ", oid_database[oid_type].oid_value[i]);
	printf(" (%s)\n", oid_database[oid_type].description);
}
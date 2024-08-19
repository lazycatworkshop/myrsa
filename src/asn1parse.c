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

#define ASN1_TAG_CONSTRUCTIVE 0x20

enum OID_TYPE {
	OID_TYPE_ISO = 0,
	OID_TYPE_EC_PUBLIC_KEY,
	OID_TYPE_SPCEP256R1,
	OID_TYPE_ECDSA_WITH_SHA256,
	OID_TYPE_RSA,
	OID_TYPE_RSA_ENCRYPTION,
	OID_TYPE_SHA256_WITH_RSA_ENCRYPTION,
	OID_TYPE_EMBEDDED_SCTS,
	OID_TYPE_AUTHORITY_INFO_ACCESS,
	OID_TYPE_SERVER_AUTH,
	OID_TYPE_CLIENT_AUTH,
	OID_TYPE_OCSP,
	OID_TYPE_CA_ISSUERS,
	OID_TYPE_COMMON_NAME,
	OID_TYPE_COUNTRY_NAME,
	OID_TYPE_ORGANIZATION_NAME,
	OID_TYPE_SUBJECT_KEY_IDENTIFIER,
	OID_TYPE_KEY_USAGE,
	OID_TYPE_SUBJECT_ALT_NAME,
	OID_TYPE_BASIC_CONSTRAINTS,
	OID_TYPE_CRL_DISTRIBUTION_POINTS,
	OID_TYPE_CERTIFICATE_POLICIES,
	OID_TYPE_AUTHORITY_KEY_IDENTIFIER,
	OID_TYPE_EXT_KEY_USAGE,
	OID_TYPE_DOMAIN_VALID,
	/* Add more OIDs as needed */

	OID_TYPE_UNKNOWN
};

const char *asn1_print_tag(uint8_t tag);
void decode_asn1_oid(uint8_t asn1_oid_value[], uint8_t asn1_oid_len,
		     uint32_t oid_value[], uint32_t *oid_len);
int asn1_lookup_oid(uint32_t asn1_oid_value[], uint32_t asn1_oid_len);
void print_oid(uint32_t oid_value[], uint32_t oid_len);
void print_oid_desc(int oid_type);
void print_indent(void);
void level_inc(uint32_t len);
void level_len_inc(uint32_t len);
void level_len_dec(uint32_t len);

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
				printf("%04ld: ", ftell(fp) - 1);
			printf("%02x ", c);
			if (++j % 16 == 0)
				printf("\n");
		}
		printf("\n");
		fseek(fp, 0, SEEK_SET);
	}

	enum ASN1_TAG {
		ASN1_TAG_EOC = 0x00,
		ASN1_TAG_BOOLEAN = 0x01,
		ASN1_TAG_INTEGER = 0x02,
		ASN1_TAG_BIT_STRING = 0x03,
		ASN1_TAG_OCTET_STRING = 0x04,
		ASN1_TAG_NULL = 0x05,
		ASN1_TAG_OBJECT_IDENTIFIER = 0x06,
		ASN1_TAG_UTF8_STRING = 0x0c,
		ASN1_TAG_RELATIVE_OID = 0x0d,
		ASN1_TAG_SEQUENCE = 0x10,
		ASN1_TAG_SET = 0x11,
		ASN1_TAG_PRINTABLE_STRING = 0x13,
		ASN1_TAG_VID_STRING = 0x15,
		ASN1_TAG_UTC = 0x17,
		ASN1_TAG_GENERALIZED_TIME = 0x18,
		ASN1_TAG_CONTEXT_SPECIFIC_0 = 0x80,
		ASN1_TAG_CONTEXT_SPECIFIC_2 = 0x82,
		ASN1_TAG_CONTEXT_SPECIFIC_3 = 0x83,
		ASN1_TAG_CONTEXT_SPECIFIC_4 = 0x84,
		ASN1_TAG_CONTEXT_SPECIFIC_6 = 0x86,
		/* Add more tags here */
		ASN1_TAG_UNKNOWN = 0xff
	};

	/* Parse the ASN.1 content */
	int is_constructive = 0;
	while ((c = getc(fp)) != EOF) {
		uint8_t length_bytes = 0;
		int length = 0;
		level_inc(1);
		printf("%04ld: ", ftell(fp) - 1);

		/*  Identifier octets */
		uint8_t tag = c;
		if (verbose_level > VERBOSE_LEVEL_INFO)
			printf("Tag: %02x ", tag);
		if (!asn1_print_tag(tag)) {
			fprintf(stderr, "Error: Unknown tag 0x%02x\n", tag);
			ret = EXIT_FAILURE;
			goto out;
		}

		/* Length octets */
		length = getc(fp);
		if (length & 0x80) {
			length_bytes = length & 0x7f;
			length = 0;
			for (int i = 0; i < length_bytes; i++) {
				length = (length << 8) | getc(fp);
			}
		}
		level_len_inc(length_bytes + 1);
		level_len_inc(length);
		print_indent();
		printf("%s  ", asn1_print_tag(tag));
		printf("L = %4d\n", length);
		if (!length)
			goto next_primitive;

		if (tag & ASN1_TAG_CONSTRUCTIVE)
			goto next_constructive;

		/* Content octets */

		if (tag == ASN1_TAG_OBJECT_IDENTIFIER) {
			uint8_t asn1_oid_value[128];
			for (int i = 0; i < length; i++) {
				asn1_oid_value[i] = getc(fp);
			}
			uint32_t oid_len = 0;
			uint32_t oid_value[128];

			decode_asn1_oid(asn1_oid_value, length, oid_value,
					&oid_len);
			int oid_type = asn1_lookup_oid(oid_value, oid_len);
			if (verbose_level >= VERBOSE_LEVEL_INFO) {
				print_oid(oid_value, oid_len);
				print_oid_desc(oid_type);
			}
			switch (oid_type) {
			case OID_TYPE_RSA_ENCRYPTION:
			case OID_TYPE_AUTHORITY_INFO_ACCESS:
			case OID_TYPE_SUBJECT_ALT_NAME:
			case OID_TYPE_AUTHORITY_KEY_IDENTIFIER:
			case OID_TYPE_CERTIFICATE_POLICIES:
			case OID_TYPE_CRL_DISTRIBUTION_POINTS:
			case OID_TYPE_KEY_USAGE:
			case OID_TYPE_EXT_KEY_USAGE:
				is_constructive = 1;
				break;
			default:
				is_constructive = 0;
				break;
			}

			goto next_primitive;
		}

		if (tag == ASN1_TAG_BIT_STRING) {
			int unused_bits = getc(fp);
			if (verbose_level >= VERBOSE_LEVEL_INFO) {
				printf("%04ld: ", ftell(fp) - 1);
				printf("%2d - Unused bits\n", unused_bits);
			}
			length--;
			level_len_dec(1);

			if (is_constructive && (length > 2))
				goto next_constructive;
		}

		if (tag == ASN1_TAG_OCTET_STRING)
			if (is_constructive && (length > 2))
				goto next_constructive;

		if (tag == ASN1_TAG_PRINTABLE_STRING || tag == ASN1_TAG_UTC ||
		    tag == ASN1_TAG_CONTEXT_SPECIFIC_2 ||
		    tag == ASN1_TAG_CONTEXT_SPECIFIC_6) {
			char printable_string[128];
			for (int i = 0; i < length; i++) {
				printable_string[i] = getc(fp);
			}
			printable_string[length] = 0;
			if (verbose_level >= VERBOSE_LEVEL_INFO) {
				printf("%04ld: ", ftell(fp) - length);
				printf("%s\n", printable_string);
			}
			goto next_primitive;
		}

		/* General primitives */
		for (int i = 0; i < length; i++) {
			c = getc(fp);
			if (verbose_level >= VERBOSE_LEVEL_INFO) {
				if (i % 16 == 0)
					printf("%04ld: ", ftell(fp) - 1);
				printf("%02x ", c);
				if (i % 16 == 15)
					printf("\n");
			}
		}
		if ((verbose_level >= VERBOSE_LEVEL_INFO) && (length % 16))
			printf("\n");

next_primitive:
		level_len_dec(length); /* Content octets */
next_constructive:
		level_len_dec(length_bytes + 1); /* Length octets */
		level_len_dec(1); /* Identifier octets */
	}

out: /* Clean up */

	if (fp)
		fclose(fp);

	return ret;
}

#define ASN1_TAG_NUM 0xdf /* Take out P/C bit */
const char *asn1_print_tag(uint8_t tag)
{
	const char *ret = NULL;

	switch (tag & ASN1_TAG_NUM) {
	case 0x00:
		ret = "EOC";
		break;
	case 0x01:
		ret = "BOOLEAN";
		break;
	case 0x02:
		ret = "INTEGER";
		break;
	case 0x03:
		ret = "BIT STRING";
		break;
	case 0x04:
		ret = "OCTET STRING";
		break;
	case 0x05:
		ret = "NULL";
		break;
	case 0x06:
		ret = "OBJECT IDENTIFIER";
		break;
	case 0x0c:
		ret = "UTF8 STRING";
		break;
	case 0x0d:
		ret = "RELATIVE OID";
		break;
	case 0x10:
		ret = "SEQUENCE";
		break;
	case 0x11:
		ret = "SET";
		break;
	case 0x13:
		ret = "PRINTABLE STRING";
		break;
	case 0x15:
		ret = "VID STRING";
		break;
	case 0x17:
		ret = "UTC TIME";
		break;
	case 0x18:
		ret = "GeneralizedTime";
		break;
	case 0x80:
		ret = "CONTEXT SPECIFIC 0";
		break;
	case 0x82:
		ret = "CONTEXT SPECIFIC 2";
		break;
	case 0x83:
		ret = "CONTEXT SPECIFIC 3";
		break;
	case 0x84:
		ret = "CONTEXT SPECIFIC 4";
		break;
	case 0x86:
		ret = "CONTEXT SPECIFIC 6";
		break;
	default:
		ret = NULL;
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
	{ .oid_len = 2, .oid_value = { 1, 2 }, .description = "iso" },
	{ 6, { 1, 2, 840, 10045, 2, 1 }, "id-ecPublicKey" }, /* RFC 5480 */
	{ 7, { 1, 2, 840, 10045, 3, 1, 7 }, "secp256r1" }, /* RFC 5480*/
	{ 7, { 1, 2, 840, 10045, 4, 3, 2 }, "ecdsa-with-SHA256" }, /* RFC 5758 */
	{ 4, { 1, 2, 840, 113549 }, "rsadsi" }, /* X.509 */
	{ 7, { 1, 2, 840, 113549, 1, 1, 1 }, "rsaEncryption" }, /* RFC 4055 */
	{ 7,
	  { 1, 2, 840, 113549, 1, 1, 11 },
	  "sha256WithRSAEncryption" }, /* RFC 4055 */
	{ 10,
	  { 1, 3, 6, 1, 4, 1, 11129, 2, 4, 2 },
	  "embedded-scts" }, /* RFC 6962 */

	/* RFC 5280 (X.509 2008)*/
	{ 9, { 1, 3, 6, 1, 5, 5, 7, 1, 1 }, "id-pe-authorityInfoAccess" },
	{ 9, { 1, 3, 6, 1, 5, 5, 7, 3, 1 }, "id-kp-serverAuth" },
	{ 9, { 1, 3, 6, 1, 5, 5, 7, 3, 2 }, "id-kp-clientAuth" },
	{ 9, { 1, 3, 6, 1, 5, 5, 7, 48, 1 }, "id-ad-ocsp" },
	{ 9, { 1, 3, 6, 1, 5, 5, 7, 48, 2 }, "id-ad-caIssuers" },

	/* X.520 */
	{ 4, { 2, 5, 4, 3 }, "id-at-commonName" },
	{ 4, { 2, 5, 4, 6 }, "id-at-countryName" },
	{ 4, { 2, 5, 4, 10 }, "id-at-organizationName" },

	/* X.509 */
	{ 4, { 2, 5, 29, 14 }, "id-ce-subjectKeyIdentifier" },
	{ 4, { 2, 5, 29, 15 }, "id-ce-keyUsage" },
	{ 4, { 2, 5, 29, 17 }, "id-ce-subjectAltName" },
	{ 4, { 2, 5, 29, 19 }, "id-ce-basicConstraints" },
	{ 4, { 2, 5, 29, 31 }, "id-ce-RLDistributionPoints" },
	{ 4, { 2, 5, 29, 32 }, "id-ce-certificatePolicies" },
	{ 4, { 2, 5, 29, 35 }, "id-ce-authorityKeyIdentifier" },
	{ 4, { 2, 5, 29, 37 }, "id-ce-extKeyUsage" },

	{ 6, { 2, 23, 140, 1, 2, 1 }, "domain-validated" },

	/* Add more OIDs as needed */
	{ 0, { 0 }, "Unknown OID" }

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
int asn1_lookup_oid(uint32_t oid_value[], uint32_t oid_len)
{
	for (int i = 0; i < sizeof(oid_database) / sizeof(OID); i++) {
		if (oid_database[i].oid_len == oid_len) {
			if (memcmp(oid_database[i].oid_value, oid_value,
				   oid_len * sizeof(uint32_t)) == 0)
				return i;
		}
	}
	return OID_TYPE_UNKNOWN;
}

void print_oid(uint32_t oid_value[], uint32_t oid_len)
{
	printf("OID: ");
	for (int i = 0; i < oid_len; i++)
		printf("%d ", oid_value[i]);
}

void print_oid_desc(int oid_type)
{
	printf(" (%s)\n", oid_database[oid_type].description);
}

char indent_str[128] = { 0 };
char *indent = &indent_str[2];
int indent_level = -1;
uint32_t level_len[128] = { 0 };

void print_indent(void)
{
	printf("%s", indent);
}

void level_inc(uint32_t len)
{
	indent_level++;
	indent_str[(indent_level << 1)] = ' ';
	indent_str[(indent_level << 1) + 1] = ' ';
	level_len[indent_level] = len;
}

void level_dec()
{
	indent_str[(indent_level << 1)] = 0;
	indent_str[(indent_level << 1) + 1] = 0;
	indent_level--;
}

void level_len_inc(uint32_t len)
{
	level_len[indent_level] += len;
}

void level_len_dec(uint32_t len)
{
	for (int i = indent_level; i > 0; i--) {
		level_len[i] -= len;
		if (level_len[i] == 0)
			level_dec();
	};
}

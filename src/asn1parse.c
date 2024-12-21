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
	OID_TYPE_SHA1_WITH_RSA_ENCRYPTION,

	/* RFC 5652 CMS/PkCS #7 */
	OID_TYPE_ID_DATA,
	OID_TYPE_ID_SIGNED_DATA,
	OID_TYPE_ID_CONTENT_TYPE,
	OID_TYPE_ID_MESSAGE_DIGEST,
	OID_TYPE_ID_SIGNING_TIME,
	OID_TYPE_ID_COUNTER_SIGNATURE,

	/* PKCS #9 */
	OID_TYPE_EMAIL_ADDRESS,
	OID_TYPE_UNSTRUCTURED_NAME,
	OID_TYPE_CHALLENGE_PASSWORD,

	/* Apple Security */
	OID_TYPE_APPLE_SECURITY_86,

	/* 311 Microsoft */
	OID_TYPE_JURISDICTION_OF_INCORPORATION_LOCALITY_NAME,
	OID_TYPE_JURISDICTION_OF_INCORPORATION_STATE_OR_PROVINCE_NAME,
	OID_TYPE_JURISDICTION_OF_INCORPORATION_COUNTRY_NAME,

	OID_TYPE_SHA256_WITH_RSA_ENCRYPTION,
	OID_TYPE_EMBEDDED_SCTS,

	/* RFC 5280 (X.509 2008)*/
	OID_TYPE_AUTHORITY_INFO_ACCESS,
	OID_TYPE_CPS,
	OID_TYPE_UNOTICE,
	OID_TYPE_SERVER_AUTH,
	OID_TYPE_CLIENT_AUTH,
	OID_TYPE_OCSP,
	OID_TYPE_CA_ISSUERS,

	/* X.520 */
	OID_TYPE_COMMON_NAME,
	OID_TYPE_SERIAL_NUMBER,
	OID_TYPE_COUNTRY_NAME,
	OID_TYPE_LOCALITY_NAME,
	OID_TYPE_STATE_OR_PROVINCE_NAME,
	OID_TYPE_ORGANIZATION_NAME,
	OID_TYPE_ORGANIZATIONAL_UNIT_NAME,
	OID_TYPE_BUSINESS_CATEGORY,

	/* X.509 RFC5280 */
	OID_TYPE_SUBJECT_KEY_IDENTIFIER,
	OID_TYPE_KEY_USAGE,
	OID_TYPE_SUBJECT_ALT_NAME,
	OID_TYPE_BASIC_CONSTRAINTS,
	OID_TYPE_CRL_DISTRIBUTION_POINTS,
	OID_TYPE_CERTIFICATE_POLICIES,
	OID_TYPE_ANY_POLICY,
	OID_TYPE_AUTHORITY_KEY_IDENTIFIER,
	OID_TYPE_EXT_KEY_USAGE,

	/* RFC 8017 PKCS #1*/
	OID_TYPE_SHA256,

	/* Digicert (11412) */
	OID_TYPE_EV_SSL_CERTIFICATES,

	OID_TYPE_EV_GUIDELINES,
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
void level_dec(void);
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
		ASN1_TAG_IA5_STRING = 0x16,
		ASN1_TAG_UTC = 0x17,
		ASN1_TAG_GENERALIZED_TIME = 0x18,
		ASN1_TAG_CONTEXT_SPECIFIC_0 = 0x80,
		ASN1_TAG_CONTEXT_SPECIFIC_1 = 0x81,
		ASN1_TAG_CONTEXT_SPECIFIC_2 = 0x82,
		ASN1_TAG_CONTEXT_SPECIFIC_3 = 0x83,
		ASN1_TAG_CONTEXT_SPECIFIC_4 = 0x84,
		ASN1_TAG_CONTEXT_SPECIFIC_6 = 0x86,
		/* Add more tags here */
		ASN1_TAG_UNKNOWN = 0xff
	};
	/* Parse the ASN.1 content */
	while ((c = getc(fp)) != EOF) {
		uint8_t length_bytes = 0;
		int length = 0;

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

		/* Match EOC tag to the indefinite content. */
		if (tag != ASN1_TAG_EOC) {
			level_inc(1);
			level_len_inc(length_bytes + 1);
			level_len_inc(length);
		}

		print_indent();
		printf("%s  ", asn1_print_tag(tag));
		printf("L = %4d\n", length);

		if (tag == ASN1_TAG_EOC) {
			level_dec(); /* Complete the indefinite content */
			continue;
		}

		if (tag == ASN1_TAG_NULL) {
			goto next_primitive;
		}

		if (!length) /* Indefinite form */
		{
			level_len_inc(0xffff); /* Indefinite length */
			continue;
		}

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
		}

		if (tag == ASN1_TAG_PRINTABLE_STRING ||
		    tag == ASN1_TAG_IA5_STRING || tag == ASN1_TAG_UTC ||
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

next_primitive: /* No more */
		level_len_dec(length); /* Content octets */
next_constructive: /* More to come */
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
	case 0x16:
		ret = "IA5 STRING";
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
	case 0x81:
		ret = "CONTEXT SPECIFIC 1";
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
	{ 7, { 1, 2, 840, 113549, 1, 1, 5 }, "sha1WithRSAEncryption" },
	{ 9,
	  { 1, 2, 840, 113549, 1, 9, 16, 2, 4 },
	  "id-aa-contentHint" }, /* RFC */

	/* RFC 5652 CMS/PKCS #7 */
	{ 7, { 1, 2, 840, 113549, 1, 7, 1 }, "id_data" },
	{ 7, { 1, 2, 840, 113549, 1, 7, 2 }, "id_signeData" },
	{ 7, { 1, 2, 840, 113549, 1, 9, 3 }, "id_contentType" },
	{ 7, { 1, 2, 840, 113549, 1, 9, 4 }, "id_messageDigest" },
	{ 7, { 1, 2, 840, 113549, 1, 9, 5 }, "id_signingTime" },
	{ 7, { 1, 2, 840, 113549, 1, 9, 6 }, "id_counterSignature" },

	/* PKCS #9 */
	{ 7, { 1, 2, 840, 113549, 1, 9, 1 }, "pkcs-9-ub-emailAddress" },
	{ 7, { 1, 2, 840, 113549, 1, 9, 2 }, "pkcs-9-ub-unstructuredName" },
	{ 7, { 1, 2, 840, 113549, 1, 9, 7 }, "pkcs-9-at-challengePassword" },

	/* Apple Security */
	{ 7, { 1, 2, 840, 113635, 100, 6, 86 }, "appleSecurity(6)?(86)" },

	/* 311 - Microsoft */
	{ 11,
	  { 1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 1 },
	  "jurisdictionOfIncorporationLocalityName" },
	{ 11,
	  { 1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 2 },
	  "jurisdictionOfIncorporationStateOrProvinceName" },
	{ 11,
	  { 1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3 },
	  "jurisdictionOfIncorporationCountryName" },

	{ 7,
	  { 1, 2, 840, 113549, 1, 1, 11 },
	  "sha256WithRSAEncryption" }, /* RFC 4055 */
	{ 10,
	  { 1, 3, 6, 1, 4, 1, 11129, 2, 4, 2 },
	  "embedded-scts" }, /* RFC 6962 */

	/* RFC 5280 (X.509 2008)*/
	{ 9, { 1, 3, 6, 1, 5, 5, 7, 1, 1 }, "id-pe-authorityInfoAccess" },
	{ 9, { 1, 3, 6, 1, 5, 5, 7, 2, 1 }, "id-qt-cps" },
	{ 9, { 1, 3, 6, 1, 5, 5, 7, 2, 2 }, "id-qt-unotice" },
	{ 9, { 1, 3, 6, 1, 5, 5, 7, 3, 1 }, "id-kp-serverAuth" },
	{ 9, { 1, 3, 6, 1, 5, 5, 7, 3, 2 }, "id-kp-clientAuth " },
	{ 9, { 1, 3, 6, 1, 5, 5, 7, 48, 1 }, "id-ad-ocsp" },
	{ 9, { 1, 3, 6, 1, 5, 5, 7, 48, 2 }, "id-ad-caIssuers" },

	/* X.520 */
	{ 4, { 2, 5, 4, 3 }, "id-at-commonName" },
	{ 4, { 2, 5, 4, 5 }, "id-at-serialNumber" },
	{ 4, { 2, 5, 4, 6 }, "id-at-countryName" },
	{ 4, { 2, 5, 4, 7 }, "id-at-localityName" },
	{ 4, { 2, 5, 4, 8 }, "id-at-stateOrProvinceName" },
	{ 4, { 2, 5, 4, 10 }, "id-at-organizationName" },
	{ 4, { 2, 5, 4, 11 }, "id-at-organizationalUnitName" },
	{ 4, { 2, 5, 4, 15 }, "id-at-businessCategory" },

	/* X.509 RFC5280 */
	{ 4, { 2, 5, 29, 14 }, "id-ce-subjectKeyIdentifier" },
	{ 4, { 2, 5, 29, 15 }, "id-ce-keyUsage" },
	{ 4, { 2, 5, 29, 17 }, "id-ce-subjectAltName" },
	{ 4, { 2, 5, 29, 19 }, "id-ce-basicConstraints" },
	{ 4, { 2, 5, 29, 31 }, "id-ce-RLDistributionPoints" },
	{ 4, { 2, 5, 29, 32 }, "id-ce-certificatePolicies" },
	{ 5, { 2, 5, 29, 32, 0 }, "id-ce-anyPolicy" },
	{ 4, { 2, 5, 29, 35 }, "id-ce-authorityKeyIdentifier" },
	{ 4, { 2, 5, 29, 37 }, "id-ce-extKeyUsage" },

	/* RFC 8017 PKCS #1*/
	{ 9, { 2, 16, 840, 1, 101, 3, 4, 2, 1 }, "id_sha256" },

	/* Digicert (11412) */
	{ 7, { 2, 16, 840, 1, 114412, 2, 1 }, "ev-ssl-certificates(2) 1" },

	{ 5, { 2, 23, 140, 1, 1 }, "ev-guidelines" },
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
char *indent = &indent_str[1];
int indent_level = -1;
uint32_t level_len[128] = { 0 };

void print_indent(void)
{
	printf("%s", indent);
}

void level_inc(uint32_t len)
{
	indent_level++;
	indent_str[indent_level] = '-';
	level_len[indent_level] = len;
}

void level_dec()
{
	indent_str[indent_level] = 0;
	level_len[indent_level] = 0;
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

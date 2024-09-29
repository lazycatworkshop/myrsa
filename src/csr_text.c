/** csr_text.c - This program present in structure text the content of a
 * Certificate Signing Request  */
#pragma pack(push, 1)

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <time.h>

enum {
	VERBOSE_LEVEL_NONE,
	VERBOSE_LEVEL_INFO,
	VERBOSE_LEVEL_DEBUG
} verbose_level = VERBOSE_LEVEL_NONE;

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

#define ASN_BOOLEAN_TRUE 0xff
#define ASN_BOOLEAN_FALSE 0x00

#define MAX_STRING_LENGTH 128

int asn1_find_tag(FILE *fp, uint8_t tag);
int asn1_get_length(FILE *fp);
int get_version(FILE *fp);
void print_name(FILE *fp, int length);
void print_public_key_info(FILE *fp);
void print_attributes(FILE *fp, int length);
void print_signature(FILE *fp);

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
			if (j % 16 == 15)
				printf("\n");
			j++;
		}
		printf("\n");
	}

	/* Parse the ASN.1 content */
	rewind(fp);
	printf("PKCS #10 Certificate Request\n\n");

	int version = get_version(fp);
	printf("  version: v%1d\n", version + 1); /* 0=v1 */

	printf("  subject: ");
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	int length = asn1_get_length(fp);
	print_name(fp, length);

	printf("  subjectPKInfo:\n");
	print_public_key_info(fp);

	printf("  attributes:\n");
	asn1_find_tag(fp, ASN1_TAG_CONTEXT_SPECIFIC_0);
	length = asn1_get_length(fp);
	print_attributes(fp, length);

	print_signature(fp);

out: /* Clean up */

	if (fp)
		fclose(fp);

	return ret;
}

int asn1_get_length(FILE *fp)
{
	/* Length octets */
	int length = getc(fp);
	int length_bytes = 0;
	if (length & 0x80) {
		length_bytes = length & 0x7f;
		length = 0;
		for (int i = 0; i < length_bytes; i++) {
			length = (length << 8) | getc(fp);
		}
	}

	return length;
}

#define ASN1_TAG_MASK 0xdf /* Take out P/C flag */
int asn1_find_tag(FILE *fp, uint8_t tag)
{
	int c;
	while ((c = getc(fp)) != EOF) {
		int t = c & ASN1_TAG_MASK;
		if (t == tag) {
			return 0;
		}
	}
	return -1;
}

int get_version(FILE *fp)
{
	asn1_find_tag(fp, ASN1_TAG_INTEGER);
	asn1_get_length(fp);
	return getc(fp);
}

enum OID_TYPE {
	OID_TYPE_ISO = 0,
	OID_TYPE_EC_PUBLIC_KEY,
	OID_TYPE_SPCEP256R1,
	OID_TYPE_ECDSA_WITH_SHA256,
	OID_TYPE_RSA,
	OID_TYPE_RSA_ENCRYPTION,
	OID_TYPE_SHA1_WITH_RSA_ENCRYPTION,
	OID_TYPE_EMAIL_ADDRESS,
	OID_TYPE_UNSTRUCTURED_NAME,
	OID_TYPE_CHALLENGE_PASSWORD,
	OID_TYPE_APPLE_SECURITY_86,
	OID_TYPE_JURISDICTION_OF_INCORPORATION_LOCALITY_NAME,
	OID_TYPE_JURISDICTION_OF_INCORPORATION_STATE_OR_PROVINCE_NAME,
	OID_TYPE_JURISDICTION_OF_INCORPORATION_COUNTRY_NAME,
	OID_TYPE_SHA256_WITH_RSA_ENCRYPTION,
	OID_TYPE_EMBEDDED_SCTS,
	OID_TYPE_AUTHORITY_INFO_ACCESS,
	OID_TYPE_CPS,
	OID_TYPE_UNOTICE,
	OID_TYPE_SERVER_AUTH,
	OID_TYPE_CLIENT_AUTH,
	OID_TYPE_OCSP,
	OID_TYPE_CA_ISSUERS,
	OID_TYPE_COMMON_NAME,
	OID_TYPE_SERIAL_NUMBER,
	OID_TYPE_COUNTRY_NAME,
	OID_TYPE_LOCALITY_NAME,
	OID_TYPE_STATE_OR_PROVINCE_NAME,
	OID_TYPE_ORGANIZATION_NAME,
	OID_TYPE_ORGANIZATIONAL_UNIT_NAME,
	OID_TYPE_BUSINESS_CATEGORY,
	OID_TYPE_SUBJECT_KEY_IDENTIFIER,
	OID_TYPE_KEY_USAGE,
	OID_TYPE_SUBJECT_ALT_NAME,
	OID_TYPE_BASIC_CONSTRAINTS,
	OID_TYPE_CRL_DISTRIBUTION_POINTS,
	OID_TYPE_CERTIFICATE_POLICIES,
	OID_TYPE_ANY_POLICY,
	OID_TYPE_AUTHORITY_KEY_IDENTIFIER,
	OID_TYPE_EXT_KEY_USAGE,
	OID_TYPE_EV_SSL_CERTIFICATES,
	OID_TYPE_EV_GUIDELINES,
	OID_TYPE_DOMAIN_VALID,
	/* Add more OIDs as needed */

	OID_TYPE_UNKNOWN
};

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
	printf("%s", oid_database[oid_type].description);
}

int get_oid(FILE *fp, int length)
{
	uint8_t asn1_oid_value[128];
	for (int i = 0; i < length; i++) {
		asn1_oid_value[i] = getc(fp);
	}
	uint32_t oid_len = 0;
	uint32_t oid_value[128];

	decode_asn1_oid(asn1_oid_value, length, oid_value, &oid_len);
	int oid_type = asn1_lookup_oid(oid_value, oid_len);

	if (oid_type == OID_TYPE_UNKNOWN) {
		printf("Unknown ");
		print_oid(oid_value, oid_len);
		printf("\n");
	}

	return oid_type;
}

void print_printable_string(FILE *fp, int length)
{
	for (int i = 0; i < length; i++) {
		printf("%c", getc(fp));
	}
}

void print_name(FILE *fp, int length)
{
	int offset1, offset2 = 0;
	while (length) {
		offset1 = ftell(fp);
		asn1_find_tag(fp, ASN1_TAG_SET);
		asn1_get_length(fp);
		asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
		asn1_get_length(fp);
		asn1_find_tag(fp, ASN1_TAG_OBJECT_IDENTIFIER);
		int l = asn1_get_length(fp);
		int oid_type = get_oid(fp, l);
		switch (oid_type) {
		case OID_TYPE_JURISDICTION_OF_INCORPORATION_COUNTRY_NAME:
			printf("jC=");
			break;
		case OID_TYPE_JURISDICTION_OF_INCORPORATION_STATE_OR_PROVINCE_NAME:
			printf("jST=");
			break;
		case OID_TYPE_JURISDICTION_OF_INCORPORATION_LOCALITY_NAME:
			printf("jL=");
			break;
		case OID_TYPE_COMMON_NAME:
			printf("CN=");
			break;
		case OID_TYPE_COUNTRY_NAME:
			printf("C=");
			break;
		case OID_TYPE_LOCALITY_NAME:
			printf("L=");
			break;
		case OID_TYPE_STATE_OR_PROVINCE_NAME:
			printf("ST=");
			break;
		case OID_TYPE_ORGANIZATION_NAME:
			printf("O=");
			break;
		case OID_TYPE_ORGANIZATIONAL_UNIT_NAME:
			printf("OU=");
			break;
		case OID_TYPE_DOMAIN_VALID:
			printf("DV=");
			break;
		case OID_TYPE_EMAIL_ADDRESS:
			printf("E=");
			break;
		case OID_TYPE_UNSTRUCTURED_NAME:
			printf("UN=");
			break;
		case OID_TYPE_CHALLENGE_PASSWORD:
			printf("CP=");
			break;
		case OID_TYPE_BUSINESS_CATEGORY:
			printf("BC=");
			break;
		case OID_TYPE_SERIAL_NUMBER:
			printf("SN=");
			break;
		default:
			printf("Unknown=");
			break;
		}

		getc(fp); /* Tag */
		l = asn1_get_length(fp);
		print_printable_string(fp, l);
		printf(", ");
		offset2 = ftell(fp);
		length -= offset2 - offset1;
	}

	printf("\n");
}

void print_rsa_public_key(FILE *fp)
{
	printf("      modulus: ");
	asn1_find_tag(fp, ASN1_TAG_INTEGER);
	int length = asn1_get_length(fp);
	if (length % 4) {
		printf("%d bits\n", (length - 1) * 8); /* Leading 0 */
	} else {
		printf("%d bits\n", length * 8);
	}

	for (int i = 0; i < length; i++) {
		printf("%02x ", getc(fp));
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}

	printf("\n      publicExponent:\n");

	asn1_find_tag(fp, ASN1_TAG_INTEGER);
	length = asn1_get_length(fp);

	for (int i = 0; i < length; i++) {
		printf("%02x ", getc(fp));
	}
	printf("\n");
}

void print_public_key_info(FILE *fp)
{
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	asn1_get_length(fp);

	printf("    algorithm: ");
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	asn1_get_length(fp);

	asn1_find_tag(fp, ASN1_TAG_OBJECT_IDENTIFIER);
	int length = asn1_get_length(fp);
	int oid_type = get_oid(fp, length);
	print_oid_desc(oid_type);
	printf("\n");

	printf("    subjectPublicKey:\n");
	if (oid_type == OID_TYPE_RSA_ENCRYPTION) {
		print_rsa_public_key(fp);
	}
	printf("\n");
}

void print_attributes(FILE *fp, int length)
{
	int offset1, offset2 = 0;
	while (length) {
		offset1 = ftell(fp);
		asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
		asn1_get_length(fp);
		asn1_find_tag(fp, ASN1_TAG_OBJECT_IDENTIFIER);
		int l = asn1_get_length(fp);
		int oid_type = get_oid(fp, l);
		printf("    ");
		print_oid_desc(oid_type);

		printf(": ");

		asn1_find_tag(fp, ASN1_TAG_SET);
		asn1_get_length(fp);
		asn1_find_tag(fp, ASN1_TAG_UTF8_STRING);
		l = asn1_get_length(fp);
		print_printable_string(fp, l);
		printf("\n");
		offset2 = ftell(fp);
		length -= offset2 - offset1;
	}

	printf("\n");
}

void print_signature(FILE *fp)
{
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	asn1_get_length(fp);

	printf("  algorithmIdentifier: ");
	asn1_find_tag(fp, ASN1_TAG_OBJECT_IDENTIFIER);
	int length = asn1_get_length(fp);
	print_oid_desc(get_oid(fp, length));

	printf("\n");

	printf("  signature:\n");
	asn1_find_tag(fp, ASN1_TAG_BIT_STRING);
	length = asn1_get_length(fp);
	for (int i = 0; i < length; i++) {
		printf("%02x ", getc(fp));
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}
	printf("\n");
}

#pragma pack(pop)

/** x509_text_public_key.c - This program takes in a public key certificate in DER
 *  format and displays its content in text.
 * 
 *  It assumes the certificate is valid in X.509 format.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <time.h>

#pragma pack(push, 1)

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

int get_version(FILE *fp);
int get_serial_number(FILE *fp, char serial_number[], size_t length);
int get_signature_algorithm_id(FILE *fp);
void print_validity(FILE *fp, size_t length);

int asn1_find_tag(FILE *fp, uint8_t tag);
int asn1_get_length(FILE *fp);
int get_oid(FILE *fp, int length);
void print_oid_desc(int oid_type);
void print_name(FILE *fp, int length);
void print_utc_time(char *utc_str);
void print_public_key_info(FILE *fp);
void print_rsa_public_key(FILE *fp);
void print_extensions(FILE *fp, int length);
void print_signature(FILE *fp);

int main(int argc, char *argv[])
{
	FILE *fp = NULL;
	int c;
	int ret = EXIT_SUCCESS;

	while ((c = getopt(argc, argv, "f:")) != -1) {
		switch (c) {
		case 'f':
			fp = fopen(optarg, "rb");
			if (fp == NULL) {
				fprintf(stderr, "Error: Unable to open file\n");
				ret = EXIT_FAILURE;
				goto out;
			}
			break;
		default:
			fprintf(stderr, "Usage: %s -f <file>\n", argv[0]);
			ret = EXIT_FAILURE;
			goto out;
		}
	}

	if (fp == NULL) {
		fprintf(stderr, "Usage: %s -f <file>\n", argv[0]);
		ret = EXIT_FAILURE;
		goto out;
	}

	/* Quick check */
	if (asn1_find_tag(fp, ASN1_TAG_CONTEXT_SPECIFIC_0) < 0) {
		fprintf(stderr, "Error: Unable to find version component\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	rewind(fp);
	printf("X509 Public Key certificate\n\n");

	printf("toBeSigned:\n");

	int version = get_version(fp);
	printf("  Version: v%1d\n", version + 1); /* 0=v1 */

	char mem_buf[MAX_STRING_LENGTH];
	memset(mem_buf, 0, MAX_STRING_LENGTH);
	int length = get_serial_number(fp, mem_buf, MAX_STRING_LENGTH);
	printf("  serial Number: ");
	for (int i = 0; i < length; i++) {
		printf("%02x ", mem_buf[i]);
	}

	printf("\n  signature: ");
	int oid = get_signature_algorithm_id(fp);
	print_oid_desc(oid);
	printf("\n");

	printf("  issuer: ");
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	length = asn1_get_length(fp);
	print_name(fp, length);

	printf("  validity:\n");
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	length = asn1_get_length(fp);
	print_validity(fp, length);

	printf("  subject: ");
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	length = asn1_get_length(fp);
	print_name(fp, length);

	printf("  subjectPublicKeyInfo:\n");
	print_public_key_info(fp);

	/* issuerUniqueIdentifier and subjectUniqueIdentifier are not
	   implemented */
	if (getc(fp) == ASN1_TAG_CONTEXT_SPECIFIC_1)
		printf("  issuerUniqueIdentifier: Not implemented\n");
	fseek(fp, -1, SEEK_CUR);

	if (version == 2 &&
	    !asn1_find_tag(fp,
			   ASN1_TAG_CONTEXT_SPECIFIC_3)) { /* Has to be v3 */
		printf("  extensions:\n");
		length = asn1_get_length(fp);
		print_extensions(fp, length);
	} else {
		printf("  extensions: None\n");
		fseek(fp, -1, SEEK_CUR);
	}

	printf("SIGNATURE:\n");
	print_signature(fp);

	ret = EXIT_SUCCESS;

out:
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

enum OID_TYPE {
	OID_TYPE_ISO = 0,
	OID_TYPE_EC_PUBLIC_KEY,
	OID_TYPE_SPCEP256R1,
	OID_TYPE_ECDSA_WITH_SHA256,
	OID_TYPE_RSA,
	OID_TYPE_RSA_ENCRYPTION,
	OID_TYPE_SHA1_WITH_RSA_ENCRYPTION,
	OID_TYPE_EMAIL_ADDRESS,
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
	{ 7, { 1, 2, 840, 113549, 1, 9, 1 }, "emailAddress" }, /* RFC 5280 */

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

	return oid_type;
}

void print_printable_string(FILE *fp, int length)
{
	for (int i = 0; i < length; i++) {
		printf("%c", getc(fp));
	}
}

int get_version(FILE *fp)
{
	asn1_find_tag(fp, ASN1_TAG_CONTEXT_SPECIFIC_0);
	asn1_get_length(fp);
	asn1_find_tag(fp, ASN1_TAG_INTEGER);
	asn1_get_length(fp);
	return getc(fp);
}

int get_serial_number(FILE *fp, char serial_number[], size_t length)
{
	asn1_find_tag(fp, ASN1_TAG_INTEGER);
	int l = asn1_get_length(fp);
	if (l > length) {
		return -1;
	}
	for (int i = 0; i < l; i++) {
		serial_number[i] = getc(fp);
	}
	return l;
}

int get_signature_algorithm_id(FILE *fp)
{
	asn1_find_tag(fp, ASN1_TAG_OBJECT_IDENTIFIER);
	int length = asn1_get_length(fp);
	return get_oid(fp, length);
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

void print_validity(FILE *fp, size_t length)
{
	int tag = getc(fp);
	fseek(fp, -1, SEEK_CUR);

	size_t offset1, offset2 = 0;
	char time_str[16];
	for (int i = 0; i < 2; i++) { /* Expect only notBefore and notAfter */
		offset1 = ftell(fp);
		memset(time_str, 0, 16);
		if (tag == ASN1_TAG_UTC) {
			asn1_find_tag(fp, ASN1_TAG_UTC);
		} else if (tag == ASN1_TAG_GENERALIZED_TIME) {
			asn1_find_tag(fp, ASN1_TAG_GENERALIZED_TIME);
		} else {
			/* Error */
		}

		int l = asn1_get_length(fp);
		for (int j = 0; j < l; j++) {
			time_str[j] = getc(fp);
		}
		if (i == 0) {
			printf("    notBefore\t: ");
		} else {
			printf("    notAfter\t: ");
		}
		printf("%s\n", time_str);
		offset2 = ftell(fp);
		length -= offset2 - offset1;
	}

	if (length) {
		printf("Unsupported time format\n");
	}
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
}

void print_public_key_info(FILE *fp)
{
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

struct sct_header {
	uint8_t version;
	uint8_t log_id[32];
	uint64_t timestamp;
	uint16_t extensions_length;
};

enum hash_alg {
	HASH_ALG_NONE = 0,
	HASH_ALG_MD5 = 1,
	HASH_ALG_SHA1 = 2,
	HASH_ALG_SHA224 = 3,
	HASH_ALG_SHA256 = 4,
	HASH_ALG_SHA384 = 5,
	HASH_ALG_SHA512 = 6,
	HASH_ALG_SHA512_224 = 7,
	HASH_ALG_SHA512_256 = 8,
	HASH_ALG_SHA3_224 = 9,
	HASH_ALG_SHA3_256 = 10,
	HASH_ALG_SHA3_384 = 11,
	HASH_ALG_SHA3_512 = 12,
	HASH_ALG_SHAKE128 = 13,
	HASH_ALG_SHAKE256 = 14,
	HASH_ALG_SM3 = 15,
	HASH_ALG_MAX
};

char *hash_alg_str[HASH_ALG_MAX] = { "None",	 "MD5",	       "SHA1",
				     "SHA224",	 "SHA256",     "SHA384",
				     "SHA512",	 "SHA512/224", "SHA512/256",
				     "SHA3-224", "SHA3-256",   "SHA3-384",
				     "SHA3-512", "SHAKE128",   "SHAKE256",
				     "SM3" };

enum sig_alg {
	SIG_ALG_NONE = 0,
	SIG_ALG_RSA = 1,
	SIG_ALG_DSA = 2,
	SIG_ALG_ECDSA = 3,
	SIG_ALG_MAX
};

char *sig_alg_str[SIG_ALG_MAX] = {
	"None",
	"RSA",
	"DSA",
	"ECDSA",
};

struct sct_signature_header {
	uint8_t hash_alg;
	uint8_t sig_alg;
	uint16_t sig_len;
};

uint16_t endian_swap_uint16(uint16_t value)
{
	return (value >> 8) | (value << 8);
};

uint64_t endian_swap_uint64(uint64_t value)
{
	value = ((value << 8) & 0xFF00FF00FF00FF00ULL) |
		((value >> 8) & 0x00FF00FF00FF00FFULL);
	value = ((value << 16) & 0xFFFF0000FFFF0000ULL) |
		((value >> 16) & 0x0000FFFF0000FFFFULL);
	return (value << 32) | (value >> 32);
};

void print_sct_timestamp(uint64_t timestamp)
{
	time_t t = timestamp / 1000;
	struct tm *tm = gmtime(&t);
	printf("      timestamp: %s", asctime(tm));
}

void print_scts(FILE *fp, size_t len)
{
	uint8_t header_buf[256];
	memset(header_buf, 0, 256);
	size_t offset1, offset2 = 0;
	int length = getc(fp);
	length = (length << 8) | getc(fp);
	if (length != len - 2) {
		printf("Error: Length mismatch\n");
		exit(EXIT_FAILURE);
	}
	while (length) {
		offset1 = ftell(fp);
		/* Don't care the length of individual SCT */
		getc(fp);
		getc(fp);

		for (int i = 0; i < 43; i++) {
			header_buf[i] = getc(fp);
		}
		struct sct_header *p = (struct sct_header *)header_buf;
		printf("      version: v%1d\n", p->version + 1);
		printf("      log_id:");
		for (int i = 0; i < 32; i++) {
			printf("%02x ", p->log_id[i]);
			if (i % 16 == 15) {
				printf("\n");
			}
		}
		p->timestamp = endian_swap_uint64(p->timestamp);
		print_sct_timestamp(p->timestamp);
		p->extensions_length = endian_swap_uint16(p->extensions_length);
		if (!p->extensions_length) {
			printf("      extensions: none\n");
		} else {
			printf("      extensions_length: %d\n",
			       p->extensions_length);
			for (int i = 0; i < p->extensions_length; i++) {
				printf("%02x ", getc(fp));
			}
			printf("\n");
		}

		memset(header_buf, 0, 256);
		for (int i = 0; i < 4; i++) {
			header_buf[i] = getc(fp);
		}
		struct sct_signature_header *q =
			(struct sct_signature_header *)p;
		printf("      hash_alg: %s\n", hash_alg_str[q->hash_alg]);
		printf("      sig_alg: %s\n", sig_alg_str[q->sig_alg]);
		q->sig_len = endian_swap_uint16(q->sig_len);
		printf("      sig_len: %d\n", q->sig_len);
		for (int i = 0; i < q->sig_len; i++) {
			printf("%02x ", getc(fp));
			if (i % 16 == 15) {
				printf("\n");
			}
		}
		printf("\n");

		offset2 = ftell(fp);
		length -= offset2 - offset1;
	}
}

void print_extensions(FILE *fp, int length)
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

		int c = getc(fp);
		int c1 = getc(fp);
		int is_critical = 0;
		if ((c & ASN1_TAG_MASK) == ASN1_TAG_BOOLEAN) {
			is_critical = c1 ? 1 : 0;

			if (is_critical) {
				printf(" critical");
			}
		}
		fseek(fp, -2, SEEK_CUR);
		printf("\n");

		asn1_find_tag(fp, ASN1_TAG_OCTET_STRING);
		switch (oid_type) {
		case OID_TYPE_AUTHORITY_KEY_IDENTIFIER:
			asn1_get_length(fp);
			asn1_find_tag(
				fp,
				ASN1_TAG_SEQUENCE); /* AuthorityKeyIdentifier */
			l = asn1_get_length(fp);
			while (l) {
				int offset11 = ftell(fp);
				int c = getc(fp);
				switch (c & ASN1_TAG_MASK) {
				case ASN1_TAG_CONTEXT_SPECIFIC_0: /* [0] keyIdentifier */
					int ll = asn1_get_length(fp);
					for (int i = 0; i < ll; i++) {
						printf("%02x ", getc(fp));
					}
					printf("\n");
					break;
				case ASN1_TAG_CONTEXT_SPECIFIC_1: /* [1] authorityCertIssuer */
					asn1_get_length(fp);
					c = getc(fp);
					switch (c & ASN1_TAG_MASK) {
					case ASN1_TAG_CONTEXT_SPECIFIC_4: /* [4] directoryName */
						asn1_get_length(fp);
						asn1_find_tag(
							fp, ASN1_TAG_SEQUENCE);
						ll = asn1_get_length(fp);
						printf("Directory Name: ");
						print_name(fp, ll);
						break;
					default:
						break;
					}
					break;
				case ASN1_TAG_CONTEXT_SPECIFIC_2: /* [2] authorityCertSerialNumber */
					ll = asn1_get_length(fp);
					printf("Serial Number: ");
					for (int i = 0; i < ll; i++) {
						printf("%02x ", getc(fp));
					}
					printf("\n");
					break;
				default:
					break;
				}
				int offset22 = ftell(fp);
				l -= offset22 - offset11;
			}

			break;
		case OID_TYPE_SUBJECT_KEY_IDENTIFIER:
			asn1_get_length(fp);
			asn1_find_tag(fp, ASN1_TAG_OCTET_STRING);
			l = asn1_get_length(fp);
			for (int i = 0; i < l; i++) {
				printf("%02x ", getc(fp));
			}
			printf("\n");
			break;
		case OID_TYPE_SUBJECT_ALT_NAME:
			asn1_get_length(fp);
			asn1_find_tag(fp, ASN1_TAG_CONTEXT_SPECIFIC_2);
			l = asn1_get_length(fp);
			print_printable_string(fp, l);
			printf("\n");
			break;
		case OID_TYPE_CERTIFICATE_POLICIES:
			asn1_get_length(fp);
			asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
			l = asn1_get_length(fp);
			while (l) { /* certificatePolicies */
				int offset1 = ftell(fp);
				asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
				size_t ll = asn1_get_length(fp);
				while (ll) { /* PolicyInformation */
					int offset11 = ftell(fp);
					asn1_find_tag(
						fp, ASN1_TAG_OBJECT_IDENTIFIER);
					int lll = asn1_get_length(fp);
					int oid_type = get_oid(
						fp, lll); /* CertPolicyId */
					print_oid_desc(oid_type);
					printf("\n");
					int offset22 = ftell(fp);
					ll -= offset22 - offset11;
					if (!ll) { /* PolicyQualifiers is optional */
						break;
					}
					offset11 = ftell(fp);
					asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
					lll = asn1_get_length(fp);
					while (lll) { /* PolicyQualifierInfo */
						int offset111 = ftell(fp);
						asn1_find_tag(
							fp,
							ASN1_TAG_OBJECT_IDENTIFIER);
						int llll = asn1_get_length(fp);
						int oid_type =
							get_oid(fp, llll);
						print_oid_desc(oid_type);
						printf("\n");

						int c = getc(fp);
						switch (c & ASN1_TAG_MASK) {
						case ASN1_TAG_IA5_STRING: /* CPSuri */
							llll = asn1_get_length(
								fp);
							print_printable_string(
								fp, llll);
							break;
						default: /* UseNotice */
							llll = asn1_get_length(
								fp);
							for (int i = 0;
							     i < llll; i++) {
								printf("%02x ",
								       getc(fp));
							}
							break;
						}
						printf("\n");
						int offset222 = ftell(fp);
						lll -= offset222 - offset111;
					}
					offset22 = ftell(fp);
					ll -= offset22 - offset11;
				}
				int offset2 = ftell(fp);
				l -= offset2 - offset1;
			}
			break;
		case OID_TYPE_KEY_USAGE:
			asn1_get_length(fp);
			asn1_find_tag(fp, ASN1_TAG_BIT_STRING);
			l = asn1_get_length(fp);
			int unused_bits = getc(fp);
			uint16_t flag = 0;
			for (int i = 0; i < l - 1; i++) {
				flag = ((flag << (i * 8)) | getc(fp));
			}
			flag >>= unused_bits;
			if (flag & 0x01) {
				printf("digitalSignature, ");
			}
			if (flag & 0x02) {
				printf("contentCommitment, ");
			}
			if (flag & 0x04) {
				printf("keyEncipherment, ");
			}
			if (flag & 0x08) {
				printf("dataEncipherment, ");
			}
			if (flag & 0x10) {
				printf("keyAgreement, ");
			}
			if (flag & 0x20) {
				printf("keyCertSign, ");
			}
			if (flag & 0x40) {
				printf("cRLSign, ");
			}
			if (flag & 0x80) {
				printf("encipherOnly, ");
			}
			if (flag & 0x100) {
				printf("decipherOnly, ");
			}
			printf("\n");
			break;
		case OID_TYPE_EXT_KEY_USAGE:
			asn1_get_length(fp);
			asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
			l = asn1_get_length(fp);
			while (l) {
				int offset1 = ftell(fp);
				asn1_find_tag(fp, ASN1_TAG_OBJECT_IDENTIFIER);
				int ll = asn1_get_length(fp);
				int oid_type = get_oid(fp, ll);
				print_oid_desc(oid_type);
				printf(",");
				int offset2 = ftell(fp);
				l -= offset2 - offset1;
			}
			printf("\n");
			break;
		case OID_TYPE_CRL_DISTRIBUTION_POINTS:
			asn1_get_length(fp);
			asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
			l = asn1_get_length(fp);
			while (l) {
				int offset1 = ftell(fp);
				asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
				asn1_get_length(fp);
				asn1_find_tag(fp, ASN1_TAG_CONTEXT_SPECIFIC_6);
				int ll = asn1_get_length(fp);
				print_printable_string(fp, ll);
				int offset2 = ftell(fp);
				l -= offset2 - offset1;
			}
			printf("\n");
			break;
		case OID_TYPE_AUTHORITY_INFO_ACCESS:
			asn1_get_length(fp);
			asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
			l = asn1_get_length(fp);
			while (l) {
				int offset1 = ftell(fp);
				asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
				asn1_get_length(fp);
				asn1_find_tag(fp, ASN1_TAG_OBJECT_IDENTIFIER);
				int ll = asn1_get_length(fp);
				int oid_type = get_oid(fp, ll);
				print_oid_desc(oid_type);
				printf(": ");
				asn1_find_tag(fp, ASN1_TAG_CONTEXT_SPECIFIC_6);
				ll = asn1_get_length(fp);
				print_printable_string(fp, ll);
				int offset2 = ftell(fp);
				l -= offset2 - offset1;
				printf("\n");
			}
			break;
		case OID_TYPE_BASIC_CONSTRAINTS:
			asn1_get_length(fp);
			asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
			l = asn1_get_length(fp);
			if (l == 0) {
				printf("CA:FALSE");
				printf("\n");
				break;
			}
			asn1_find_tag(fp, ASN1_TAG_BOOLEAN);
			asn1_get_length(fp);
			if (getc(fp) == ASN_BOOLEAN_TRUE) {
				printf("CA:TRUE, ");
			} else {
				printf("CA:FALSE, ");
			}
			if (l > 5) { /* Optional */
				asn1_find_tag(fp, ASN1_TAG_INTEGER);
				asn1_get_length(fp);
				printf("pathLenConstraint:%d", getc(fp));
			}
			printf("\n");
			break;

		case OID_TYPE_EMBEDDED_SCTS:
			asn1_get_length(fp);
			asn1_find_tag(fp, ASN1_TAG_OCTET_STRING);
			l = asn1_get_length(fp);
			print_scts(fp, l);
			break;
		default:
			l = asn1_get_length(fp);
			for (int i = 0; i < l; i++) {
				printf("%02x ", getc(fp));
				if ((i + 1) % 16 == 0) {
					printf("\n");
				}
			}
			printf("\n");
			break;
		}
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
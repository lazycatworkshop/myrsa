/** p7b_text.c - A program to display the content of .p7b file in text.
 * 
 *  Usage : p7bview -f <filename>
 * 
 * Note: This program is a work on progress and does only minimal checks.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <errno.h>
#include <locale.h>

#pragma pack(push, 1)

#define ASN1_TAG_MASK 0xdf /* Take out P/C flag */

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
	ASN1_TAG_CONTEXT_SPECIFIC_5 = 0x85,
	ASN1_TAG_CONTEXT_SPECIFIC_6 = 0x86,
	ASN1_TAG_CONTEXT_SPECIFIC_7 = 0x87,
	ASN1_TAG_CONTEXT_SPECIFIC_8 = 0x88,
	/* Add more tags here */
	ASN1_TAG_UNKNOWN = 0xff
};

#define ASN1_INDEFINITE_FORM 0x80
#define ASN1_INDEFINITE_LENGTH 0xffff

#define ASN_BOOLEAN_TRUE 0xff
#define ASN_BOOLEAN_FALSE 0x00

#define MAX_STRING_LENGTH 128

int asn1_find_tag(FILE *fp, uint8_t tag);
int asn1_get_length(FILE *fp);
int get_content_type(FILE *fp);
int process_content(FILE *fp, int oid);

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
				fprintf(stderr,
					"Error: Failed to open file '%s' - %s\n",
					optarg, strerror(errno));
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

	c = getc(fp);
	if (c == '-') { /* Encapsulate Boundary in PEM */
		fprintf(stderr, "Error: File is in PEM format\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	fseek(fp, 0, SEEK_SET);

	/* Top level: ContentInfo */
	if (asn1_find_tag(fp, ASN1_TAG_SEQUENCE) < 0) {
		fprintf(stderr, "Error: Failed to find the first SEQUENCE.\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	asn1_get_length(fp);

	int oid = get_content_type(fp);
	if (!process_content(fp, oid)) {
		fprintf(stderr, "Error: Not a valid PKCS #7 file\n\n");
		ret = EXIT_FAILURE;
		goto out;
	}

out:
	if (fp)
		fclose(fp);
	return ret;
}

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

int asn1_get_length(FILE *fp)
{
	/* Length octets */
	int length_bytes = 0;
	int length = getc(fp);
	if (length != ASN1_INDEFINITE_FORM) {
		if (length & 0x80) {
			length_bytes = length & 0x7f;
			length = 0;
			for (int i = 0; i < length_bytes; i++) {
				length = (length << 8) | getc(fp);
			}
		}
	} else {
		length = ASN1_INDEFINITE_LENGTH;
	}

	return length;
}

enum OID_TYPE {
	OID_TYPE_ISO = 0,
	OID_TYPE_EC_PUBLIC_KEY,
	OID_TYPE_SPCEP256R1,
	OID_TYPE_ECDSA_WITH_SHA256,
	OID_TYPE_RSA,
	OID_TYPE_RSA_ENCRYPTION,
	OID_TYPE_SHA1_WITH_RSA_ENCRYPTION,
	OID_TYPE_CONTENT_HINT,

	/* RFC 5652 CMS/PkCS #7 */
	OID_TYPE_ID_DATA,
	OID_TYPE_ID_SIGNED_DATA,
	OID_TYPE_ID_CONTENT_TYPE,
	OID_TYPE_ID_MESSAGE_DIGEST,
	OID_TYPE_ID_SIGNING_TIME,
	OID_TYPE_ID_COUNTER_SIGNATURE,

	OID_TYPE_SMIME_CAPABILITIES, /* RFC 8551*/

	/* PKCS #9 */
	OID_TYPE_EMAIL_ADDRESS,
	OID_TYPE_UNSTRUCTURED_NAME,
	OID_TYPE_CHALLENGE_PASSWORD,

	/* RFC 6211 */
	OID_TYPE_CMS_ALGORITHM_PROTECTION,

	/* RFC 8018 */
	OID_TYPE_RC2_CBC,
	OID_TYPE_DES_EDE3_CBC,

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

	/* RFC 8018 */
	OID_TYPE_DES_CBC,

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
	OID_TYPE_SUBJECT_DIRECTORY_ATTRIBUTES,
	OID_TYPE_SUBJECT_KEY_IDENTIFIER,
	OID_TYPE_KEY_USAGE,
	OID_TYPE_SUBJECT_ALT_NAME,
	OID_TYPE_BASIC_CONSTRAINTS,
	OID_TYPE_CRL_DISTRIBUTION_POINTS,
	OID_TYPE_CERTIFICATE_POLICIES,
	OID_TYPE_ANY_POLICY,
	OID_TYPE_AUTHORITY_KEY_IDENTIFIER,
	OID_TYPE_EXT_KEY_USAGE,

	/* RFC 3565 */
	OID_TYPE_AES128_CBC,
	OID_TYPE_AES192_CBC,
	OID_TYPE_AES256_CBC,

	/* RFC 8017 PKCS #1*/
	OID_TYPE_SHA256,

	/* Digicert (11412) */
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
	{ 9,
	  { 1, 2, 840, 113549, 1, 9, 16, 2, 4 },
	  "id-aa-contentHint" }, /* RFC 2634 */

	/* RFC 5652 CMS/PKCS #7 */
	{ 7, { 1, 2, 840, 113549, 1, 7, 1 }, "id_data" },
	{ 7, { 1, 2, 840, 113549, 1, 7, 2 }, "id_signedData" },
	{ 7, { 1, 2, 840, 113549, 1, 9, 3 }, "id_contentType" },
	{ 7, { 1, 2, 840, 113549, 1, 9, 4 }, "id_messageDigest" },
	{ 7, { 1, 2, 840, 113549, 1, 9, 5 }, "id_signingTime" },
	{ 7, { 1, 2, 840, 113549, 1, 9, 6 }, "id_counterSignature" },

	{ 7,
	  { 1, 2, 840, 113549, 1, 9, 15 },
	  "smimeCapabilities" }, /* RFC 8551 */

	/* PKCS #9 */
	{ 7, { 1, 2, 840, 113549, 1, 9, 1 }, "pkcs-9-ub-emailAddress" },
	{ 7, { 1, 2, 840, 113549, 1, 9, 2 }, "pkcs-9-ub-unstructuredName" },
	{ 7, { 1, 2, 840, 113549, 1, 9, 7 }, "pkcs-9-at-challengePassword" },

	/* RFC 6211 */
	{ 7, { 1, 2, 840, 113549, 1, 9, 52 }, "id-aa-CMSAlgorithmProtection" },

	/* RFC 8018 */
	{ 6, { 1, 2, 840, 113549, 3, 2 }, "rc2CBC" },
	{ 6, { 1, 2, 840, 113549, 3, 7 }, "des-EDE3-CBC" },

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

	/* RFC 8018 */
	{ 6, { 1, 3, 14, 3, 2, 7 }, "desCBC" },

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
	{ 4, { 2, 5, 29, 9 }, "id-ce-subjectDirectoryAttributes" },
	{ 4, { 2, 5, 29, 14 }, "id-ce-subjectKeyIdentifier" },
	{ 4, { 2, 5, 29, 15 }, "id-ce-keyUsage" },
	{ 4, { 2, 5, 29, 17 }, "id-ce-subjectAltName" },
	{ 4, { 2, 5, 29, 19 }, "id-ce-basicConstraints" },
	{ 4, { 2, 5, 29, 31 }, "id-ce-RLDistributionPoints" },
	{ 4, { 2, 5, 29, 32 }, "id-ce-certificatePolicies" },
	{ 5, { 2, 5, 29, 32, 0 }, "id-ce-anyPolicy" },
	{ 4, { 2, 5, 29, 35 }, "id-ce-authorityKeyIdentifier" },
	{ 4, { 2, 5, 29, 37 }, "id-ce-extKeyUsage" },

	/* RFC 3565 */
	{},
	{ 9, { 2, 16, 840, 1, 101, 3, 4, 1, 2 }, "id-aes128-CBC" },
	{ 9, { 2, 16, 840, 1, 101, 3, 4, 1, 22 }, "id-aes192-CBC" },
	{ 9, { 2, 16, 840, 1, 101, 3, 4, 1, 42 }, "id-aes256-CBC" },

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
	printf("%s", oid_database[oid_type].description);
}

int asn1_get_oid_type(FILE *fp)
{
	asn1_find_tag(fp, ASN1_TAG_OBJECT_IDENTIFIER);
	int length = asn1_get_length(fp);
	uint8_t asn1_oid_value[128];
	for (int i = 0; i < length; i++) {
		asn1_oid_value[i] = getc(fp);
	}
	uint32_t oid_len = 0;
	uint32_t oid_value[128];

	decode_asn1_oid(asn1_oid_value, length, oid_value, &oid_len);
	int oid_type = asn1_lookup_oid(oid_value, oid_len);

#ifdef DEBUG
	if (oid_type == OID_TYPE_UNKNOWN) {
		printf("Unknown ");
		print_oid(oid_value, oid_len);
		printf("\n");
	}
#endif

	return oid_type;
}

int asn1_get_oid(FILE *fp, int length, uint8_t oid_value[], uint32_t *oid_len)
{
	for (int i = 0; i < length; i++) {
		oid_value[i] = getc(fp);
	}
	*oid_len = length;

	return 1;
}

int asn1_print_object_identifier(FILE *fp)
{
	asn1_find_tag(fp, ASN1_TAG_OBJECT_IDENTIFIER);
	int length = asn1_get_length(fp);
	uint8_t asn1_oid_value[128];
	uint32_t oid_len = 0;
	asn1_get_oid(fp, length, asn1_oid_value, &oid_len);

	uint32_t oid_value[128];
	decode_asn1_oid(asn1_oid_value, oid_len, oid_value, &oid_len);
	int oid_type = asn1_lookup_oid(oid_value, oid_len);

	if (oid_type != OID_TYPE_UNKNOWN) {
		print_oid_desc(oid_type);
	} else {
		print_oid(oid_value, oid_len);
	}

	return oid_type;
}

int asn1_get_integer(FILE *fp)
{
	asn1_find_tag(fp, ASN1_TAG_INTEGER);
	int length = asn1_get_length(fp);
	int value = 0;
	for (int i = 0; i < length; i++) {
		value = (value << 8) | getc(fp);
	}
	return value;
}

int is_eoc_next(FILE *fp)
{
	int c = getc(fp);
	if (c == ASN1_TAG_EOC) {
		asn1_get_length(fp);
		return 1;
	}
	ungetc(c, fp);
	return 0;
}

int get_content_type(FILE *fp)
{
	/* ContentType ::= OBJECT IDENTIFIER */
	printf("Content Type: ");
	int oid_type = asn1_print_object_identifier(fp);
	printf("\n");

	return oid_type;
}

int process_signed_data(FILE *fp);
int process_id_data(FILE *fp);

int process_content(FILE *fp, int oid)
{
	int ret = 0;
	switch (oid) {
	case OID_TYPE_ID_SIGNED_DATA:
		ret = process_signed_data(fp);
		break;
	case OID_TYPE_ID_DATA:
		ret = process_id_data(fp);
		break;
	default:
		ret = 0;
	}

	return ret;
}

int process_digest_algorithms(FILE *fp);
int process_encapsulated_content_info(FILE *fp);
int process_certificates(FILE *fp);
int process_signer_infos(FILE *fp);
int process_signed_data(FILE *fp)
{
	printf("Signed Data\n");

	/* For structures of indefinite form, if thye are consisting of only
	 * simple structures, just remove EOC when we reach it.
	 */
	asn1_find_tag(fp, ASN1_TAG_CONTEXT_SPECIFIC_0);
	asn1_get_length(fp); /* Assume indefinite form #1. */

	asn1_find_tag(fp, ASN1_TAG_SEQUENCE); /* Assume indefinite form #2. */
	asn1_get_length(fp);

	asn1_find_tag(fp, ASN1_TAG_INTEGER);
	asn1_get_length(fp);
	int version = getc(fp);
	printf("  Version: v%1d\n", version); /* 0=v1 */

	process_digest_algorithms(fp);

	process_encapsulated_content_info(fp);

	/* certificates field is optional */
	process_certificates(fp);

	process_signer_infos(fp);

	if (is_eoc_next(fp)) /* Indefinite form #2 */
		return 1;

	if (is_eoc_next(fp)) /* Indefinite form #1 */
		return 1;

	return 1;
}

int process_algorithm_identifier(FILE *fp)
{
	/* AlgorithmIdentifier ::= SEQUENCE {
	 *    algorithm OBJECT IDENTIFIER,
	 *    parameters ANY DEFINED BY algorithm OPTIONAL
	 * }
	 */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	int length = asn1_get_length(fp);
	int offset1, offset2 = 0;
	offset1 = ftell(fp);

	asn1_print_object_identifier(fp);

	offset2 = ftell(fp);
	length -= offset2 - offset1;

	/* Parameter field is optional */
	if (length) {
		int c = getc(fp);
		if ((c & ASN1_TAG_MASK) == ASN1_TAG_NULL) {
			asn1_get_length(fp); /* Just read the length */
			printf("\n");
		} else
			return 0; /* Not supprted yet */
	}

	return 1;
}

int process_digest_algorithms(FILE *fp)
{
	/* DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier */
	asn1_find_tag(fp, ASN1_TAG_SET);
	int length = asn1_get_length(fp);
	printf("  Digest Algorithms: ");

	if (!length) { /* Certificate-only PKCS#7 structure */
		printf("Empty\n");
		return 1;
	}

	/* DigestAlgorithmIdentifier ::= AlgorithmIdentifier */
	int offset1, offset2 = 0;
	while (length) { /* Nnumbere of algorithms */
		offset1 = ftell(fp);
		process_algorithm_identifier(fp);
		offset2 = ftell(fp);
		length -= offset2 - offset1;

		if (is_eoc_next(fp)) /* Indefinite form */
			length = 0;

		if (length)
			printf(", ");
	}

	printf("\n");

	return 1;
}

int process_e_content_type(FILE *fp)
{
	/* ContentType ::= OBJECT IDENTIFIER */
	printf("    eContent Type: ");

	int oid_type = asn1_print_object_identifier(fp);
	printf("\n");

	return oid_type;
}

int process_encapsulated_content_info(FILE *fp)
{
	/* EncapsulatedContentInfo ::= SEQUENCE {
		eContentType ContentType,
		eContent [0] EXPLICIT OCTET STRING OPTIONAL }
	 */
	printf("  encapsulatedContentInfo:\n");

	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	int length = asn1_get_length(fp); /* Assume indefinite form #1*/
	int offset1, offset2 = 0;
	offset1 = ftell(fp);

	int oid = process_e_content_type(fp);

	offset2 = ftell(fp);
	length -= offset2 - offset1;

	if (!length) /* eContent is optional */
		return 1;

	int c = getc(fp);
	if ((c & ASN1_TAG_MASK) == ASN1_TAG_CONTEXT_SPECIFIC_0) { /* Optional */
		printf("    eContent:\n");

		asn1_get_length(fp); /* Assume indefinite form #2 */

		if (!process_content(fp, oid)) {
			fprintf(stderr,
				"Error: Not a valid PKCS #7 content type!\n\n");
			return 0;
		}

		if (is_eoc_next(fp)) {
		} /* Indefinite form #2 */

	} else { /* Put back the read-ahead. */
		ungetc(c, fp);
		return 1;
	}

	if (is_eoc_next(fp)) /* Indefinite form #1 */
		return 1;

	return 1; /* Fixed form */
}

int print_octet_string(FILE *fp, int length)
{
	for (int i = 0; i < length; i++) {
		int c = getc(fp);
		printf("%02x ", c);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}

	return 1;
}

void print_printable_string(FILE *fp, int length)
{
	char str[MAX_STRING_LENGTH];
	for (int i = 0; i < length; i++) {
		str[i] = getc(fp);
	}
	str[length] = '\0';
	printf("%s", str);
}

void print_utf8_string(FILE *fp, int length)
{
	/* TODO: verify the necessity of setting locale.
	setlocale(LC_ALL, "en_US.UTF-8");
	 */
	print_printable_string(fp, length);
}

void print_ia5_string(FILE *fp, int length)
{
	/* Piggyback off printable for now */
	print_printable_string(fp, length);
}

void print_bit_string(FILE *fp, int length)
{
	int unused_bits = getc(fp);
	printf("unused bits: %d\n", unused_bits);
	print_octet_string(fp, length - 1);
}

int process_id_data(FILE *fp)
{
	asn1_find_tag(fp, ASN1_TAG_OCTET_STRING);
	int length = asn1_get_length(fp);

	if (length == ASN1_INDEFINITE_LENGTH) { /* Indefinite form */

		asn1_find_tag(fp, ASN1_TAG_OCTET_STRING);
		length = asn1_get_length(fp);
	}
	print_octet_string(fp, length);

	printf("\n");

	if (is_eoc_next(fp)) /* Indefinite form */
		return 1;

	return 1;
}

int process_x509_cert(FILE *fp);
int process_certificates(FILE *fp)
{
	/* certificates [0] IMPLICIT CertificateSet OPTIONAL */
	int c = getc(fp);
	if ((c & ASN1_TAG_MASK) == ASN1_TAG_CONTEXT_SPECIFIC_0) {
		asn1_get_length(fp); /* Assume indefinite form */
		process_x509_cert(fp);
		if (is_eoc_next(fp)) /* Indefinite form */
			return 1;
	} else
		ungetc(c, fp);

	return 1;
}

enum X509_VERSION { X509_VERSION_V1 = 0, X509_VERSION_V2, X509_VERSION_V3 };

int x509_get_version(FILE *fp);
int x509_process_certificate_serial_number(FILE *fp);
int x509_process_algorithm_idenfifier(FILE *fp);
int x501_process_name(FILE *fp);
int x509_process_validity(FILE *fp);
int x509_process_subject_public_key_info(FILE *fp);
int x509_process_extensions(FILE *fp);
int x509_process_signature(FILE *fp);
int process_x509_cert(FILE *fp)
{
	/* Top level */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	asn1_get_length(fp);

	/* Top level */
	printf("X509 Public Key certificate\n\n");

	printf("toBeSigned:\n");

	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	asn1_get_length(fp);

	int version = x509_get_version(fp);
	printf("  Version: v%1d\n", version + 1); /* 0=v1 */

	x509_process_certificate_serial_number(fp);

	printf("\n  signature: ");
	x509_process_algorithm_idenfifier(fp);

	printf("  issuer: ");
	x501_process_name(fp);

	printf("  validity:\n");
	x509_process_validity(fp);

	printf("  subject: ");
	x501_process_name(fp);

	printf("  subjectPublicKeyInfo:\n");
	x509_process_subject_public_key_info(fp);

	/* issuerUniqueIdentifier and subjectUniqueIdentifier are not
	   implemented */
	int c = getc(fp);
	if ((c & ASN1_TAG_MASK) == ASN1_TAG_CONTEXT_SPECIFIC_1)
		printf("  issuerUniqueIdentifier: Not implemented\n");
	else
		ungetc(c, fp);

	c = getc(fp);
	if (version > X509_VERSION_V1 &&
	    ((c & ASN1_TAG_MASK) == ASN1_TAG_CONTEXT_SPECIFIC_2)) {
		printf("  subjectUniqueIdentifier: Not implemented\n");
	} else
		ungetc(c, fp);

	c = getc(fp);
	if (version > X509_VERSION_V1 &&
	    ((c & ASN1_TAG_MASK) == ASN1_TAG_CONTEXT_SPECIFIC_3)) {
		printf("  extensions:\n");
		asn1_get_length(fp);
		x509_process_extensions(fp);
	} else
		ungetc(c, fp);

	printf("SIGNATURE:\n");
	x509_process_signature(fp);

	return 1;
}

int x509_get_version(FILE *fp)
{
	int c = getc(fp);
	if ((c & ASN1_TAG_MASK) == ASN1_TAG_CONTEXT_SPECIFIC_0) {
		asn1_get_length(fp);
		asn1_find_tag(fp, ASN1_TAG_INTEGER);
		asn1_get_length(fp); /* Assume L=1 */
		return getc(fp);
	} else {
		ungetc(c, fp);
		return X509_VERSION_V1;
	}
}

int x509_process_certificate_serial_number(FILE *fp)
{
	asn1_find_tag(fp, ASN1_TAG_INTEGER);
	int length = asn1_get_length(fp);
	printf("  serial Number: ");
	for (int i = 0; i < length; i++) {
		printf("%02x ", getc(fp));
	}

	return length;
}

int x509_process_algorithm_idenfifier(FILE *fp)
{
	/* AlgorithmIdentifier ::= SEQUENCE {
	 *    algorithm OBJECT IDENTIFIER,
	 *    parameters ANY DEFINED BY algorithm OPTIONAL
	 * }
	 */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	int length = asn1_get_length(fp);
	int offset1, offset2 = 0;
	offset1 = ftell(fp);

	asn1_print_object_identifier(fp);
	printf("\n");

	offset2 = ftell(fp);
	length -= offset2 - offset1;

	/* Parameter field is optional */
	if (length) {
		int c = getc(fp);
		if ((c & ASN1_TAG_MASK) == ASN1_TAG_NULL) {
			asn1_get_length(fp); /* Just read the length */
		} else
			return 0; /* Not supprted yet */
	}

	return 1;
}

int x501_process_rdn_sequence(FILE *fp, int length);
void print_time(int day, int month, int year, int hour, int minute, int second);
int x501_process_name(FILE *fp)
{
	/* Only RDNSequence now */
	/* RDNSequence ::= SEQUENCE OF RelativeDistinguishedName */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	int length = asn1_get_length(fp);
	x501_process_rdn_sequence(fp, length);

	return 1;
}

int print_oid_label(int oid_type)
{
	switch (oid_type) {
	case OID_TYPE_JURISDICTION_OF_INCORPORATION_COUNTRY_NAME:
		printf("jC");
		break;
	case OID_TYPE_JURISDICTION_OF_INCORPORATION_STATE_OR_PROVINCE_NAME:
		printf("jST");
		break;
	case OID_TYPE_JURISDICTION_OF_INCORPORATION_LOCALITY_NAME:
		printf("jL");
		break;
	case OID_TYPE_COMMON_NAME:
		printf("CN");
		break;
	case OID_TYPE_COUNTRY_NAME:
		printf("C");
		break;
	case OID_TYPE_LOCALITY_NAME:
		printf("L");
		break;
	case OID_TYPE_STATE_OR_PROVINCE_NAME:
		printf("ST");
		break;
	case OID_TYPE_ORGANIZATION_NAME:
		printf("O");
		break;
	case OID_TYPE_ORGANIZATIONAL_UNIT_NAME:
		printf("OU");
		break;
	case OID_TYPE_DOMAIN_VALID:
		printf("DV");
		break;
	case OID_TYPE_EMAIL_ADDRESS:
		printf("E");
		break;
	case OID_TYPE_UNSTRUCTURED_NAME:
		printf("UN");
		break;
	case OID_TYPE_CHALLENGE_PASSWORD:
		printf("CP");
		break;
	case OID_TYPE_BUSINESS_CATEGORY:
		printf("BC");
		break;
	case OID_TYPE_SERIAL_NUMBER:
		printf("SN");
		break;
	default:
		printf("Unknown");
		break;
	}

	return 1;
}

int process_attributde_type_and_value(FILE *fp)
{
	/* AttributeTypeAndValue ::= SEQUENCE {
	 *    type  OBJECT IDENTIFIER,
	 *    value ANY DEFINED BY type
	 * }
	 */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	asn1_get_length(fp);

	/* type */
	int oid_type = asn1_get_oid_type(fp);
	print_oid_label(oid_type);

	printf("=");

	/* value ANY */
	int c = getc(fp);
	int length = asn1_get_length(fp);

	/* Support only printable string now. */
	switch (c & ASN1_TAG_MASK) {
	case ASN1_TAG_PRINTABLE_STRING:
		print_printable_string(fp, length);
		break;
	case ASN1_TAG_UTF8_STRING:
		print_utf8_string(fp, length);
		break;
	case ASN1_TAG_IA5_STRING:
		print_ia5_string(fp, length);
		break;

	default:
		fprintf(stderr,
			"Error: Not a supported AttributeTypeAndValue\n");
		return 0;
		break;
	}

	return 1;
}

int x501_process_rdn_sequence(FILE *fp, int length)
{
	/* RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue */

	int offset1, offset2 = 0;
	while (length) {
		offset1 = ftell(fp);
		asn1_find_tag(fp, ASN1_TAG_SET);
		asn1_get_length(fp);

		process_attributde_type_and_value(fp);

		offset2 = ftell(fp);
		length -= offset2 - offset1;
		if (length)
			printf(", ");
	}

	printf("\n");

	return 1;
}

void print_time(int day, int month, int year, int hour, int minute, int second)
{
	// Month names
	const char *months[] = {
		"January",   "February", "March",    "April",
		"May",	     "June",	 "July",     "August",
		"September", "October",	 "November", "December"
	};

	// Print the formatted date and time
	printf("%d%s %s %d, %02d:%02d:%02d UTC\n", day,
	       (day == 1 || day == 21 || day == 31) ? "st" :
	       (day == 2 || day == 22)		    ? "nd" :
	       (day == 3 || day == 23)		    ? "rd" :
						      "th",
	       months[month - 1], year, hour, minute, second);
}

/** print_utc_time - print the UTC time included in the input character string to
 *  the stdout as readable text
 * 
 * @utc_str: input string containing the UTC time 
 * 
 * */
void print_utc_time(char *utc_str)
{
	int year, month, day, hour, minute, second;

	// Extract the time components from the UTC string
	sscanf(utc_str, "%2d%2d%2d%2d%2d%2d", &year, &month, &day, &hour,
	       &minute, &second);

	// Assuming the year is in the 21st century (20xx)
	year += 2000;

	print_time(day, month, year, hour, minute, second);
}

void print_generalized_time(char *generalized_time)
{
	int year, month, day, hour, minute, second;

	// Extract the time components from the Generalized time string
	sscanf(generalized_time, "%4d%2d%2d%2d%2d%2d", &year, &month, &day,
	       &hour, &minute, &second);

	print_time(day, month, year, hour, minute, second);
}

int asn1_print_utc_time(FILE *fp)
{
	/* UTCTime ::= YYMMDDHHMMSSZ */
	asn1_find_tag(fp, ASN1_TAG_UTC);
	int length = asn1_get_length(fp);
	char time_str[16];
	for (int i = 0; i < length; i++) {
		time_str[i] = getc(fp);
	}

	print_utc_time(time_str);

	return 1;
}

int asn1_print_generalized_time(FILE *fp)
{
	/* GeneralizedTime ::= YYYYMMDDHHMMSSZ */
	asn1_find_tag(fp, ASN1_TAG_GENERALIZED_TIME);
	int length = asn1_get_length(fp);
	char time_str[16];
	for (int i = 0; i < length; i++) {
		time_str[i] = getc(fp);
	}

	print_generalized_time(time_str);

	return 1;
}

int x509_process_validity(FILE *fp)
{
	/* Validity ::= SEQUENCE {
	 *    notBefore Time,
	 *    notAfter Time
	 * }
	 */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	asn1_get_length(fp);

	char *time_label[] = { "    notBefore", "    notAfter" };
	char time_str[16];
	for (int i = 0; i < 2; i++) {
		printf("  %s\t: ", time_label[i]);

		int c = getc(fp);
		int length = asn1_get_length(fp);
		for (int i = 0; i < length; i++) {
			time_str[i] = getc(fp);
		}
		switch (c & ASN1_TAG_MASK) {
		case ASN1_TAG_UTC:
			print_utc_time(time_str);
			break;
		case ASN1_TAG_GENERALIZED_TIME:
			print_generalized_time(time_str);
			break;
		default:
			fprintf(stderr, "Error: Not a valid time\n");
			return 0;
			break;
		}
	}

	return 1;
}

int x509_process_subject_public_key_info(FILE *fp)
{
	/* SubjectPublicKeyInfo ::= SEQUENCE {
	 *    algorithm AlgorithmIdentifier,
	 *    subjectPublicKey BIT STRING
	 * }
	 */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	asn1_get_length(fp);

	printf("    algorithm: ");
	x509_process_algorithm_idenfifier(fp);

	asn1_find_tag(fp, ASN1_TAG_BIT_STRING);
	asn1_get_length(fp);
	printf("    subjectPublicKey: ");
	printf(" unused bits: %d\n", getc(fp));

	/* Print the public key */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	asn1_get_length(fp);
	asn1_find_tag(fp, ASN1_TAG_INTEGER);
	printf("    Modulus:\n");
	int length = asn1_get_length(fp);
	int c = getc(fp);
	if (!c) /* Remove leading 0 */
		length--;
	for (int i = 0; i < length; i++) {
		printf("%02x ", getc(fp));
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}
	printf("\n");

	asn1_find_tag(fp, ASN1_TAG_INTEGER);
	printf("    Exponent:\n");
	length = asn1_get_length(fp);
	for (int i = 0; i < length; i++) {
		printf("%02x ", getc(fp));
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}
	printf("\n");

	return 1;
}

int x509_process_authority_key_identifier(FILE *fp)
{
	/* AuthorityKeyIdentifier ::= SEQUENCE {
	 *    keyIdentifier [0] IMPLICIT KeyIdentifier OPTIONAL,
	 *    authorityCertIssuer [1] IMPLICIT GeneralNames OPTIONAL,
	 *    authorityCertSerialNumber [2] IMPLICIT CertificateSerialNumber OPTIONAL
	 * }
	 */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	int length = asn1_get_length(fp);
	int offset1, offset2 = 0;

	while (length) {
		offset1 = ftell(fp);

		int c = getc(fp);
		int tag = c & ASN1_TAG_MASK;
		switch (tag) {
		case ASN1_TAG_CONTEXT_SPECIFIC_0:
			/* KeyIdentifier ::= OCTET STRING */
			/* IMPLICIT: no OCTET tag*/
			int l = asn1_get_length(fp);
			print_octet_string(fp, l);
			break;
		case ASN1_TAG_CONTEXT_SPECIFIC_1:
		case ASN1_TAG_CONTEXT_SPECIFIC_2:
			fprintf(stderr,
				"Error: Not implemented AuthorityKeyIdentifier\n");
			return 0;
			break;
		default:
			fprintf(stderr,
				"Error: Not a valid AuthorityKeyIdentifier\n");
			return 0;
			break;
		}

		offset2 = ftell(fp);
		length -= offset2 - offset1;
	}

	return 1;
}

int x509_process_general_name(FILE *fp)
{
	/* GeneralName ::= CHOICE {
	 *    otherName [0] IMPLICIT OtherName,
	 *    rfc822Name [1] IMPLICIT IA5String,
	 *    dNSName [2] IMPLICIT IA5String,
	 *    x400Address [3] IMPLICIT ORAddress,
	 *    directoryName [4] IMPLICIT Name,
	 *    ediPartyName [5] IMPLICIT EDIPartyName,
	 *    uniformResourceIdentifier [6] IMPLICIT IA5String,
	 *    iPAddress [7] IMPLICIT OCTET STRING,
	 *    registeredID [8] IMPLICIT OBJECT IDENTIFIER
	 * }
	 */
	int c = getc(fp);
	int tag = c & ASN1_TAG_MASK;
	int length = asn1_get_length(fp);
	switch (tag) {
	case ASN1_TAG_CONTEXT_SPECIFIC_1:
	case ASN1_TAG_CONTEXT_SPECIFIC_2:
	case ASN1_TAG_CONTEXT_SPECIFIC_6:
		print_ia5_string(fp, length);
		break;
	case ASN1_TAG_CONTEXT_SPECIFIC_0:
	case ASN1_TAG_CONTEXT_SPECIFIC_3:
	case ASN1_TAG_CONTEXT_SPECIFIC_4:
	case ASN1_TAG_CONTEXT_SPECIFIC_5:
	case ASN1_TAG_CONTEXT_SPECIFIC_7:
	case ASN1_TAG_CONTEXT_SPECIFIC_8:
		fprintf(stderr, "Error: Not implemented GeneralName\n");
		return 0;
		break;

	default:
		fprintf(stderr, "Error: Not a valid GeneralName\n");
		return 0;
		break;
	}

	printf("\n");

	return 1;
}

int x509_process_general_names(FILE *fp)
{
	/* GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	int length = asn1_get_length(fp);

	int offset1, offset2 = 0;
	while (length) {
		offset1 = ftell(fp);

		x509_process_general_name(fp);

		offset2 = ftell(fp);
		length -= offset2 - offset1;
	}

	return 1;
}

int x509_process_policy_qualifiers(FILE *fp)
{
	/* PolicyQualifiers ::= SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	int length = asn1_get_length(fp);

	int offset1, offset2 = 0;
	while (length) {
		offset1 = ftell(fp);

		/* PolicyQualifierInfo ::= SEQUENCE {
		 *    policyQualifierId OBJECT IDENTIFIER,
		 *    qualifier ANY
		 * }
		 */
		asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
		asn1_get_length(fp);

		/* policyQualifierId */
		asn1_print_object_identifier(fp);

		printf(": ");

		/* qualifier */
		int c = getc(fp);
		int l = asn1_get_length(fp);
		switch (c & ASN1_TAG_MASK) {
		case ASN1_TAG_IA5_STRING:
			print_printable_string(fp, l);
			break;
		default:
			fprintf(stderr,
				"Error: Not a valid PolicyQualifierInfo\n");
			return 0;
			break;
		}

		offset2 = ftell(fp);
		length -= offset2 - offset1;
	}

	return 1;
}

int x509_process_policy_information(FILE *fp)
{
	/* PolicyInformation ::= SEQUENCE {
	 *    policyIdentifier OBJECT IDENTIFIER,
	 *    policyQualifiers SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL
	 * }
	 */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	int length = asn1_get_length(fp);
	int offset1, offset2 = 0;
	offset1 = ftell(fp);

	/* policyIdentifier */
	asn1_print_object_identifier(fp);

	printf("\n");

	offset2 = ftell(fp);
	length -= offset2 - offset1;

	if (!length)
		return 1;

	x509_process_policy_qualifiers(fp);

	return 1;
}

int x509_process_certificate_policies(FILE *fp)
{
	/* CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	int length = asn1_get_length(fp);

	int offset1, offset2 = 0;
	while (length) {
		offset1 = ftell(fp);

		x509_process_policy_information(fp);

		offset2 = ftell(fp);
		length -= offset2 - offset1;
	}

	return 1;
}

int x509_process_basic_constraints(FILE *fp)
{
	/* BasicConstraints ::= SEQUENCE {
	 *    cA BOOLEAN DEFAULT FALSE,
	 *    pathLenConstraint INTEGER (0..MAX) OPTIONAL
	 * }
	 */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	int length = asn1_get_length(fp);
	if (!length) {
		printf("    CA: FALSE\n");
		return 1;
	}
	int offset1, offset2 = 0;
	offset1 = ftell(fp);

	int c = getc(fp);
	if ((c & ASN1_TAG_MASK) == ASN1_TAG_BOOLEAN) {
		asn1_get_length(fp);
		int cc = getc(fp);
		printf("    CA: %s\n",
		       cc == ASN_BOOLEAN_TRUE ? "TRUE" : "FALSE");
	} else
		ungetc(c, fp);

	offset2 = ftell(fp);
	length -= offset2 - offset1;

	/* pathLenConstraint */
	if (!length) /* Optional */
		return 1;

	asn1_find_tag(fp, ASN1_TAG_INTEGER);
	asn1_get_length(fp);
	int cc = getc(fp);
	printf("    Path Length Constraint: %d\n", cc);

	return 1;
}

int x509_process_key_usage(FILE *fp)
{
	/* KeyUsage ::= BIT STRING */
	asn1_find_tag(fp, ASN1_TAG_BIT_STRING);
	int length = asn1_get_length(fp);
	int unused_bits = getc(fp);
	uint16_t flag = 0;
	for (int i = 0; i < length - 1; i++) {
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

	return 1;
}

int x509_process_authority_info_access(FILE *fp)
{
	/* AuthorityInfoAccessSyntax  ::=
	 * SEQUENCE SIZE (1..MAX) OF AccessDescription
	 */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	int length = asn1_get_length(fp);

	int offset1, offset2 = 0;
	while (length) {
		offset1 = ftell(fp);

		/* AccessDescription ::= SEQUENCE {
		 *    accessMethod OBJECT IDENTIFIER,
		 *    accessLocation GeneralName
		 * }
		 */
		asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
		asn1_get_length(fp);

		/* accessMethod */
		asn1_print_object_identifier(fp);

		printf(": ");

		/* accessLocation */
		x509_process_general_name(fp);

		offset2 = ftell(fp);
		length -= offset2 - offset1;
	}

	return 1;
}

int x509_process_ext_key_usage(FILE *fp)
{
	/* ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	int length = asn1_get_length(fp);

	int offset1, offset2 = 0;
	while (length) {
		offset1 = ftell(fp);

		asn1_print_object_identifier(fp);

		offset2 = ftell(fp);
		length -= offset2 - offset1;

		if (length)
			printf(", ");
	}

	return 1;
}

int x509_process_distribution_point_name(FILE *fp)
{
	/* DistributionPointName ::= CHOICE {
	 *    fullName [0] GeneralNames,
	 *    nameRelativeToCRLIssuer [1] RelativeDistinguishedName
	 * }
	 */
	int c = getc(fp);
	int tag = c & ASN1_TAG_MASK;
	asn1_get_length(fp);
	switch (tag) {
	case ASN1_TAG_CONTEXT_SPECIFIC_0:
		/* NOTE: supposed to be names but test samples does not match it. */
		x509_process_general_name(fp);
		break;
	case ASN1_TAG_CONTEXT_SPECIFIC_1:
		fprintf(stderr,
			"Error: Not implemented DistributionPointName\n");
		return 0;
		break;
	default:
		fprintf(stderr, "Error: Not a valid DistributionPointName\n");
		return 0;
		break;
	}

	return 1;
}

int x509_process_distribution_point(FILE *fp)
{
	/* DistributionPoint ::= SEQUENCE {
	 *    distributionPoint [0] DistributionPointName OPTIONAL,
	 *    reasons [1] ReasonFlags OPTIONAL,
	 *    cRLIssuer [2] GeneralNames OPTIONAL
	 * }
	 */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	asn1_get_length(fp);

	int c = getc(fp);
	if ((c & ASN1_TAG_MASK) == ASN1_TAG_CONTEXT_SPECIFIC_0) {
		/* DistributionPointName ::= CHOICE {
		 *    fullName [0] GeneralNames,
		 *    nameRelativeToCRLIssuer [1] RelativeDistinguishedName
		 * }
		 */
		asn1_get_length(fp);
		x509_process_distribution_point_name(fp);
	}

	return 1;
}

int x509_process_crl_distribution_points(FILE *fp)
{
	/* CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	int length = asn1_get_length(fp);
	int offset1, offset2 = 0;
	offset1 = ftell(fp);

	while (length) {
		offset1 = ftell(fp);

		x509_process_distribution_point(fp);

		offset2 = ftell(fp);
		length -= offset2 - offset1;
	}

	return 1;
}

int x509_process_subject_directory_attribute(FILE *fp)
{
	/* Attribute ::= SEQUENCE {
		 *    type OBJECT IDENTIFIER,
		 *    value SET OF ANY
		 * }
	*/
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	asn1_get_length(fp);

	/* type */
	asn1_print_object_identifier(fp);

	printf(": ");

	/* value */
	asn1_find_tag(fp, ASN1_TAG_SET);
	asn1_get_length(fp);
	int c = getc(fp);
	switch (c & ASN1_TAG_MASK) {
	case ASN1_TAG_PRINTABLE_STRING:
		int l = asn1_get_length(fp);
		print_printable_string(fp, l);
		break;
	case ASN1_TAG_OBJECT_IDENTIFIER:
		ungetc(c, fp);
		asn1_print_object_identifier(fp);
		break;
	default:
		fprintf(stderr, "Error: Not a valid Attribute\n");
		return 0;
		break;
	}

	printf("\n");

	return 1;
}

int x509_process_subject_directory_attributes(FILE *fp)
{
	/* subjectDirectoryAttributes EXTENSION ::= {
	 *	SYNTAX AttributesSyntax
	 *	IDENTIFIED BY id-ce-subjectDirectoryAttributes }
	 *	AttributesSyntax ::= SEQUENCE SIZE (1..MAX) OF Attribute
	 */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	int length = asn1_get_length(fp);

	int offset1, offset2 = 0;
	while (length) {
		offset1 = ftell(fp);

		x509_process_subject_directory_attribute(fp);

		offset2 = ftell(fp);
		length -= offset2 - offset1;
	}

	return 1;
}

/* It hsa more entries than defined in RFC 5246.
 * I forgot where it come from. */
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

#define CT_V1_HASH_LENGTH 32

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

/***********************************************
 * RFC 6962, v1
 * opaque SerializedSCT<1..2^16-1>;
 *  struct {
 *    SerializedSCT sct_list <1..2^16-1>;
 *  } SignedCertificateTimestampList;
 * 
 * From 3.2. Structure of the Signed Certificate Timestamp
 * struct {
 *	Version sct_version;
 *	LogID id;
 * 	uint64 timestamp;
 *	CtExtensions extensions;
 *	digitally-signed struct {
 *		Version sct_version;
 * 		SignatureType signature_type = certificate_timestamp;
 *		uint64 timestamp;
 *		LogEntryType entry_type;
 * 		select(entry_type) {
 * 		case x509_entry: ASN.1Cert;
 * 		case precert_entry: PreCert;
 * 		} signed_entry;
 *		CtExtensions extensions;
 *	};
 * } SignedCertificateTimestamp;
 */

/* I have difficulties to understand exactly digitally-signed struct.
 * But I found find the following from RFC 5246:
 *
 * enum {
 *	none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
 *	sha512(6), (255)
 * } HashAlgorithm;
 * enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
 * SignatureAlgorithm;
 * 
 * struct {
 *	SignatureAndHashAlgorithm algorithm;
 *	opaque signature<0..2^16-1>;
 * } DigitallySigned;
 * 
 * struct {
 *	HashAlgorithm hash;
 *	SignatureAlgorithm signature;
 * } SignatureAndHashAlgorithm;
 */

/* From RFC 5246: 
 * " 
 * Variable-length vectors are defined by specifying a subrange of legal
 * lengths, inclusively, using the notation <floor..ceiling>. When
 * these are encoded, the actual length precedes the vector’s contents
 * in the byte stream. The length will be in the form of a number
 * consuming as many bytes as required to hold the vector’s specified
 * maximum (ceiling) length.
 * "
 * 
 * So it would have three inserted 16-bit length fields for:
 * 	@Very beginning: Total length
 * 		@Each SCT:
 * 		- SCT length
 * 		- Extensions length
 * 		- Signature length
 * 
 * 16-bit length fields are sufficient for SerializedSCT<1..2^16-1>.
 */

struct sct_header {
	uint8_t version;
	uint8_t log_id[CT_V1_HASH_LENGTH];
	uint64_t timestamp;
	uint16_t extensions_length; /* Inserted for the extensions */
};

struct sct_signature_header {
	uint8_t hash_alg;
	uint8_t sig_alg;
	uint16_t sig_len; /* Inserted for the signature. */
};

/***********************************************/

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

void print_byte_buffer(uint8_t *buf, int len)
{
	for (int i = 0; i < len; i++) {
		printf("%02x ", buf[i]);
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}

	printf("\n");
}

/**
 * process_scts - Process the SignedCertificateTimestampList extension
 * @fp: File pointer to the input data
 *
 * This function processes the SignedCertificateTimestampList extension
 * and prints the SCTs.
 * 
 * Support  only v1, RFC 6962.
 *
 * Return: 1 on success, 0 on failure
 */
int process_scts(FILE *fp)
{
	/* SignedCertificateTimestampList ::= OCTET STRING */
	asn1_find_tag(fp, ASN1_TAG_OCTET_STRING);
	asn1_get_length(fp);

	/* Total length: 16 bits , big endian */
	int length = getc(fp) << 8 | getc(fp);

	while (length) {
		/* Individual SCT length */
		int l = getc(fp) << 8 | getc(fp);

		uint8_t header_buf[256];
		memset(header_buf, 0, sizeof(header_buf));
		fread((void *)header_buf, 1, sizeof(struct sct_header), fp);

		struct sct_header *p = (struct sct_header *)header_buf;
		printf("      version: v%1d\n", p->version + 1);
		printf("      log_id:");
		print_byte_buffer(p->log_id, CT_V1_HASH_LENGTH);
		print_sct_timestamp(endian_swap_uint64(p->timestamp));

		if (!p->extensions_length) {
			printf("      extensions: none\n");
		} else {
			printf("      extensions_length: %d\n",
			       p->extensions_length);
			print_octet_string(fp, p->extensions_length);
			printf("\n");
		}

		memset(header_buf, 0, sizeof(header_buf));
		for (int i = 0; i < sizeof(struct sct_signature_header); i++) {
			header_buf[i] = getc(fp);
		}
		struct sct_signature_header *q =
			(struct sct_signature_header *)header_buf;

		printf("      hash_alg: %s\n", hash_alg_str[q->hash_alg]);
		printf("      sig_alg: %s\n", sig_alg_str[q->sig_alg]);
		q->sig_len = endian_swap_uint16(q->sig_len);
		printf("      sig_len: %d\n", q->sig_len);
		print_octet_string(fp, q->sig_len);

		length -= l + 2; /* SCT size + length bytes */
	}

	return 1;
}

int x509_process_extension(FILE *fp)
{
	/* Extension ::= SEQUENCE {
	 *    extnID OBJECT IDENTIFIER,
	 *    critical BOOLEAN DEFAULT FALSE,
	 *    extnValue OCTET STRING
	 * }
	 */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	asn1_get_length(fp);

	printf("    ");
	int oid_type = asn1_print_object_identifier(fp);

	printf(": ");

	int c = getc(fp);
	if ((c & ASN1_TAG_MASK) == ASN1_TAG_BOOLEAN) {
		asn1_get_length(fp);
		int cc = getc(fp);
		printf("%s",
		       cc == ASN_BOOLEAN_TRUE ? "critical" : "non-critical");
	} else {
		printf("non-critical");
		ungetc(c, fp);
	}
	printf("\n");

	/* extnValue */
	asn1_find_tag(fp, ASN1_TAG_OCTET_STRING);
	int length = asn1_get_length(fp);
	switch (oid_type) {
	case OID_TYPE_AUTHORITY_KEY_IDENTIFIER:
		x509_process_authority_key_identifier(fp);
		break;
	case OID_TYPE_SUBJECT_KEY_IDENTIFIER:
		/* SubjectKeyIdentifier ::= KeyIdentifier */
		/* KeyIdentifier ::= OCTET STRING */
		asn1_find_tag(fp, ASN1_TAG_OCTET_STRING);
		length = asn1_get_length(fp);
		print_octet_string(fp, length);
		break;
	case OID_TYPE_SUBJECT_ALT_NAME:
		/* subjectAltName EXTENSION ::= {
		   SYNTAX GeneralNames
		   IDENTIFIED BY id-ce-subjectAltName }
		 */
		x509_process_general_names(fp);
		break;
	case OID_TYPE_CERTIFICATE_POLICIES:
		x509_process_certificate_policies(fp);
		break;
	case OID_TYPE_BASIC_CONSTRAINTS:
		x509_process_basic_constraints(fp);
		break;
	case OID_TYPE_AUTHORITY_INFO_ACCESS:
		x509_process_authority_info_access(fp);
		break;
	case OID_TYPE_KEY_USAGE:
		x509_process_key_usage(fp);
		break;
	case OID_TYPE_EXT_KEY_USAGE:
		x509_process_ext_key_usage(fp);
		break;
	case OID_TYPE_CRL_DISTRIBUTION_POINTS:
		x509_process_crl_distribution_points(fp);
		break;
	case OID_TYPE_EMBEDDED_SCTS:
		/* RFC 6962 v1 */
		process_scts(fp);
		break;
	case OID_TYPE_SUBJECT_DIRECTORY_ATTRIBUTES:
		x509_process_subject_directory_attributes(fp);
		break;
	default:
		printf("    Unknown: ");
		print_octet_string(fp, length);
		break;
	}

	printf("\n");

	return 1;
}

int x509_process_extensions(FILE *fp)
{
	/* Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	int length = asn1_get_length(fp);

	int offset1, offset2 = 0;
	while (length) {
		offset1 = ftell(fp);

		x509_process_extension(fp);

		offset2 = ftell(fp);
		length -= offset2 - offset1;
	}

	return 1;
}

int x509_process_signature(FILE *fp)
{
	/* SIGNED{ToBeSigned} ::= SEQUENCE {
         *    toBeSigned ToBeSigned,
	 *     COMPONENTS OF SIGNATURE,
	*/
	/* Signature ::= SEQUENCE {
	 *    algorithm AlgorithmIdentifier,
	 *    signature BIT STRING
	 * }
	 */
	printf("  algorithmidentifier: ");
	x509_process_algorithm_idenfifier(fp);

	printf("  signature: ");
	asn1_find_tag(fp, ASN1_TAG_BIT_STRING);
	int length = asn1_get_length(fp);
	print_bit_string(fp, length);
	printf("\n");

	return 1;
}

int print_serial_number(FILE *fp)
{
	/* CertificateSerialNumber ::= INTEGER */
	asn1_find_tag(fp, ASN1_TAG_INTEGER);
	int length = asn1_get_length(fp);
	for (int i = 0; i < length; i++) {
		printf("%02x", getc(fp));
	}

	return 1;
}

int process_issuer_and_serial_number(FILE *fp)
{
	/* IssuerAndSerialNumber ::= SEQUENCE {
	 *    issuer Name,
	 *    serialNumber CertificateSerialNumber
	 * }
	 */
	//asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	//asn1_get_length(fp);

	printf("    issuer: ");
	x501_process_name(fp);

	printf("\n");

	/* CertificateSerialNumber ::= INTEGER */
	printf("    serialNumber: ");
	print_serial_number(fp);
	printf("\n");

	return 1;
}

int process_signer_identifier(FILE *fp)
{
	/* SignerIdentifier ::= CHOICE {
	 *    issuerAndSerialNumber IssuerAndSerialNumber,
	 *    subjectKeyIdentifier [0] SubjectKeyIdentifier
	 * }
	 */
	int c = getc(fp);
	int tag = c & ASN1_TAG_MASK;
	asn1_get_length(fp);
	switch (tag) {
	case ASN1_TAG_CONTEXT_SPECIFIC_0:
		/* SubjectKeyIdentifier ::= KeyIdentifier */
		/* KeyIdentifier ::= OCTET STRING */
		asn1_find_tag(fp, ASN1_TAG_OCTET_STRING);
		int length = asn1_get_length(fp);
		print_octet_string(fp, length);
		break;
	case ASN1_TAG_SEQUENCE:
		process_issuer_and_serial_number(fp);
		break;
	default:
		fprintf(stderr, "Error: Not a valid SignerIdentifier\n");
		return 0;
		break;
	}

	return 1;
}

int print_object_identifier(FILE *fp, int length)
{
	uint8_t asn1_oid_value[128];
	uint32_t oid_len = 0;
	asn1_get_oid(fp, length, asn1_oid_value, &oid_len);

	uint32_t oid_value[128];
	decode_asn1_oid(asn1_oid_value, oid_len, oid_value, &oid_len);
	int oid_type = asn1_lookup_oid(oid_value, oid_len);

	if (oid_type != OID_TYPE_UNKNOWN) {
		print_oid_desc(oid_type);
	} else {
		print_oid(oid_value, oid_len);
	}

	return oid_type;
}

int process_cms_algorithm_protection(FILE *fp)
{
	/* CMSAlgorithmProtection ::= SEQUENCE {
	 *	digestAlgorithm DigestAlgorithmIdentifier,
	 *	signatureAlgorithm [1] SignatureAlgorithmIdentifier OPTIONAL,
	 *	macAlgorithm [2] MessageAuthenticationCodeAlgorithm
	 *	OPTIONAL
	 */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	asn1_get_length(fp);

	printf("digestAlgorithm: ");
	x509_process_algorithm_idenfifier(fp);

	int c = getc(fp);
	if ((c & ASN1_TAG_MASK) == ASN1_TAG_CONTEXT_SPECIFIC_1) {
		int length = asn1_get_length(fp);
		int offset1, offset2 = 0;
		offset1 = ftell(fp);
		/* SignatureAlgorithmIdentifier ::= AlgorithmIdentifier */
		printf("signatureAlgorithm: ");
#if 0
		/* Somehow my test samples does not have the SEQUENCE */
		x509_process_algorithm_idenfifier(fp);
#else
		asn1_find_tag(fp, ASN1_TAG_OBJECT_IDENTIFIER);
		int l = asn1_get_length(fp);
		print_object_identifier(fp, l);

		offset2 = ftell(fp);
		length -= offset2 - offset1;
		/* Parameter is optional */
		if (length) {
			/* Assume NULL */
			c = getc(fp);
			if ((c & ASN1_TAG_MASK) == ASN1_TAG_NULL) {
				asn1_get_length(fp);
				/* No printout */
			} else
				return 0; /*  Not supported yet */
		}
#endif

	} else if ((c & ASN1_TAG_MASK) == ASN1_TAG_CONTEXT_SPECIFIC_2) {
		printf("      macAlgorithm: ");
		x509_process_algorithm_idenfifier(fp);
	} else
		ungetc(c, fp);

	return 1;
}

int process_smime_capabililty(FILE *fp)
{
	/* SMIMECapability ::= SEQUENCE {
	 *	capabilityID OBJECT IDENTIFIER,
	 *	parameters ANY DEFINED BY capabilityID OPTIONAL
	 * }
	 */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	int length = asn1_get_length(fp);
	int offset1, offset2 = 0;
	offset1 = ftell(fp);

	int oid_type = asn1_print_object_identifier(fp);

	offset2 = ftell(fp);
	length -= offset2 - offset1;

	/* parameters is optional */
	if (length > 0) {
		printf(": ");

		switch (oid_type) {
		case OID_TYPE_RC2_CBC:
			int d = asn1_get_integer(fp);
			printf("%d", d);
			break;
		default:
			print_octet_string(fp, length);
			break;
		}
	}

	printf("\n");

	return 1;
}

int process_smime_capabilities(FILE *fp)
{
	/* SMIMECapabilities ::= SEQUENCE OF SMIMECapability */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	int length = asn1_get_length(fp);

	int offset1, offset2 = 0;
	while (length) {
		offset1 = ftell(fp);

		process_smime_capabililty(fp);

		offset2 = ftell(fp);
		length -= offset2 - offset1;
	}

	return 1;
}

int process_signed_attribute(FILE *fp)
{
	/* Attribute ::= SEQUENCE {
	 *	attrType OBJECT IDENTIFIER,
	 * 	attrValues SET OF AttributeValue }
	 *
	 * 	AttributeValue ::= ANY
	 */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	asn1_get_length(fp);

	printf("    type: ");
	int oid_type = asn1_print_object_identifier(fp);

	printf("\n");

	printf("    values:\n");
	asn1_find_tag(fp, ASN1_TAG_SET);
	int length = asn1_get_length(fp);
	int offset1, offset2 = 0;
	while (length) {
		offset1 = ftell(fp);

		switch (oid_type) {
		case OID_TYPE_ID_CONTENT_TYPE:
			asn1_print_object_identifier(fp);
			break;
		case OID_TYPE_ID_SIGNING_TIME:
			int c = getc(fp);
			if ((c & ASN1_TAG_MASK) == ASN1_TAG_UTC) {
				ungetc(c, fp);
				asn1_print_utc_time(fp);
			} else if ((c & ASN1_TAG_MASK) ==
				   ASN1_TAG_GENERALIZED_TIME) {
				ungetc(c, fp);
				asn1_print_generalized_time(fp);
			} else
				printf("TODO: tag %02x\n", c);

			break;
		case OID_TYPE_CMS_ALGORITHM_PROTECTION:
			process_cms_algorithm_protection(fp);
			break;
		case OID_TYPE_ID_MESSAGE_DIGEST:
			/* MessageDigest ::= OCTET STRING*/
			asn1_find_tag(fp, ASN1_TAG_OCTET_STRING);
			int len = asn1_get_length(fp);
			print_octet_string(fp, len);
			break;
		case OID_TYPE_CONTENT_HINT:
			/* ContentHints ::= SEQUENCE {
			 *	contentType ContentType,
			 *	contentDescription [0] EXPLICIT UTF8String OPTIONAL
			 * }
			 * ContentType ::= OBJECT IDENTIFIER
			 * ContentDescription ::= UTF8String
			 * 
			 * My sample shows only UTF8String.
			 */
			asn1_find_tag(fp, ASN1_TAG_UTF8_STRING);
			print_utf8_string(fp, asn1_get_length(fp));
			break;
		case OID_TYPE_SMIME_CAPABILITIES:
			/* SMIMECapabilities ::= SEQUENCE OF SMIMECapability */
			process_smime_capabilities(fp);
			break;

		default:
			print_octet_string(fp, length);
			break;
		}

		offset2 = ftell(fp);
		length -= offset2 - offset1;
		if (length)
			printf(", ");
	}

	printf("\n");

	return 1;
}

int process_signed_attributes(FILE *fp)
{
	/* SignedAttributes ::= SET SIZE (1..MAX) OF Attribute */
	int length = asn1_get_length(fp);
	int offset1, offset2 = 0;
	while (length) {
		offset1 = ftell(fp);

		process_signed_attribute(fp);
		printf("\n");

		offset2 = ftell(fp);
		length -= offset2 - offset1;
	}

	return 1;
}

int process_signer_info(FILE *fp)
{
	/* SignerInfo ::= SEQUENCE {
	 *    version CMSVersion,
	 *    sid SignerIdentifier,
	 *    digestAlgorithm DigestAlgorithmIdentifier,
	 *    signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
	 *    signatureAlgorithm SignatureAlgorithmIdentifier,
	 *    signature SignatureValue,
	 *    unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL
	 * }
	 */
	asn1_find_tag(fp, ASN1_TAG_SEQUENCE);
	asn1_get_length(fp);

	/* CMSVersion ::= INTEGER { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) } */
	asn1_find_tag(fp, ASN1_TAG_INTEGER);
	asn1_get_length(fp);
	int version = getc(fp);
	printf("  version: v%1d\n", version);

	/* sid */
	printf("  sid:\n");
	process_signer_identifier(fp);
	printf("\n");

	/* digestAlgorithm */
	printf("  digestAlgorithm: ");
	x509_process_algorithm_idenfifier(fp);

	/* signedAttrs: optional */
	int c = getc(fp);
	if ((c & ASN1_TAG_MASK) == ASN1_TAG_CONTEXT_SPECIFIC_0) {
		printf("  signedAttrs:\n");
		process_signed_attributes(fp);

	} else
		ungetc(c, fp);

	/* signatureAlgorithm */
	printf("  signatureAlgorithm: ");
	x509_process_algorithm_idenfifier(fp);

	printf("  signature:\n");
	/* SignatureValue ::= OCTET STRING */
	asn1_find_tag(fp, ASN1_TAG_OCTET_STRING);
	int length = asn1_get_length(fp);
	print_octet_string(fp, length);

	c = getc(fp);
	if ((c & ASN1_TAG_MASK) == ASN1_TAG_CONTEXT_SPECIFIC_1) {
		/* UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute */
		printf("  unsignedAttrs: ");
		process_signed_attributes(fp);
	} else
		ungetc(c, fp);

	return 1;
}

int process_signer_infos(FILE *fp)
{
	printf("SignerInfos:\n");

	/* SignerInfos ::= SET SIZE (1..MAX) OF SignerInfo */
	asn1_find_tag(fp, ASN1_TAG_SET);
	int length = asn1_get_length(fp);

	if (!length)
		printf("Empty\n");

	int offset1, offset2 = 0;
	while (length) {
		offset1 = ftell(fp);

		process_signer_info(fp);

		offset2 = ftell(fp);
		length -= offset2 - offset1;
	}

	return 1;
}

#pragma pack(pop)
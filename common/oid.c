/** oid.c - Common functions for Object Identifiers */
#include <string.h>
#include "oid.h"

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
	{ 4, { 2, 5, 4, 97 }, "id-at-organizationIdentifier" },

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
		if (i != (oid_len - 1)) /* Not last one */
			printf("%d.", oid_value[i]);
		else
			printf("%d", oid_value[i]);
}

void print_oid_desc(int oid_type)
{
	printf("%s", oid_database[oid_type].description);
}

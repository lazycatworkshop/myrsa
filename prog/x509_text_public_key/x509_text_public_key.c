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
#include <errno.h>
#include <locale.h>
#include "asn1.h"
#include "oid.h"

#pragma pack(push, 1)

#define MAX_STRING_LENGTH 256

int asn1_find_tag(FILE *fp, uint8_t tag);
int asn1_get_length(FILE *fp);
int process_x509_cert(FILE *fp);

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
					"Error: Unable to open file: %s\n",
					strerror(errno));
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

	/* version check */
	if ((getc(fp) & ASN1_TAG_MASK) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Not a valid X.509 certificate\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	rewind(fp);

	if (!process_x509_cert(fp)) {
		fprintf(stderr, "Error: Failed to process X.509 certificate\n");
		ret = EXIT_FAILURE;
	}

	ret = EXIT_SUCCESS;

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

int print_octet_string(FILE *fp, int length)
{
	for (int i = 0; i < length; i++) {
		int c = getc(fp);
		printf("%02x ", c);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}
	printf("\n");

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
			printf("\n");
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
	case OID_TYPE_ORGANIZATION_IDENTIFIER:
		printf("OI");
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
	case ASN1_TAG_T61_STRING:
		/* Temporary */
		print_printable_string(fp, length);
		break;
	case ASN1_TAG_IA5_STRING:
		print_ia5_string(fp, length);
		break;


	default:
		printf("Error: Not a supported AttributeTypeAndValue\n");
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

		if (!x509_process_general_name(fp))
			return 0;

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
		/* Temporary workaround*/
		while (ASN1_IS_CONSTRUCTED(c)) /* Assume text */
		{
			c = getc(fp);
			l = asn1_get_length(fp);
		}

		switch (c & ASN1_TAG_MASK) {
		case ASN1_TAG_IA5_STRING:
			print_printable_string(fp, l);
			break;
		case ASN1_TAG_UTF8_STRING:
			print_utf8_string(fp, l);
			break;
		default:
			fprintf(stderr,
				"Error: Not a valid PolicyQualifierInfo\n");
			return 0;
			break;
		}

		printf("\n");

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

#pragma pack(pop)
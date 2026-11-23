/* x509.c - Implementation file for X.509 certificate handling */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "x509.h"
#include "oid.h"
#include "big_number.h"
#include "memfp.h"

#define MAX_STRING_LENGTH 256

/**
 * process_x509_certificate() - Top-level pass breaking the certificate into
 * its main components.
 *
 * @asn1_buf: Pointer to the certificate buffer.
 * @cert_len: Length of the certificate buffer.
 * @cert: Pointer to the ASN1_X509Certificate structure to populate.
 * 
 * Use memfp to track the buffer pointer. This helps handling EOCs.
 * 
 * Return: 0 on success, -1 on failure.
 */
int process_x509_certificate(X509Certificate *cert)
{
	struct memfp mp;
	memfp_open(&mp, cert->asn1_buf, cert->cert_len);

	/* Top level */
	int c = mgetc(&mp);
	if (asn1_get_tag(c) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Not a valid X.509 certificate\n");
		return -1;
	}
	asn1_get_length(&mp); /* Advacne to value */

	if (asn1_load_tag(&mp, &cert->TBSCertificate, ASN1_TAG_SEQUENCE) != 0) {
		fprintf(stderr, "Error: Unable to load TBSCertificate\n");
		return -1;
	}

	if (asn1_load_tag(&mp, &cert->signatureAlgorithm, ASN1_TAG_SEQUENCE) !=
	    0) {
		fprintf(stderr, "Error: Not a valid signatureAlgorithm\n");
		return -1;
	}

	if (asn1_load_tag(&mp, &cert->signatureValue, ASN1_TAG_BIT_STRING) !=
	    0) {
		fprintf(stderr, "Error: Not a valid signatureValue\n");
		return -1;
	}

	/* Check if we've consumed all the data */
	if ((size_t)mtell(&mp) != cert->cert_len) {
		fprintf(stderr,
			"Error:  Certificate process does not end at file size\n");
		return -1;
	}

	return 0;
}

int X509_process_TBSCertificate(X509Certificate *cert)
{
	if (asn1_get_tag(cert->TBSCertificate.tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Not a valid TBSCertificate\n");
		return -1;
	}
	struct memfp mp;
	memfp_open(&mp, cert->TBSCertificate.value,
		   cert->TBSCertificate.length);
	mseek(&mp, 0, SEEK_END);
	long end = mtell(&mp);
	mseek(&mp, 0, SEEK_SET);

	/* Sub-components */
	int c = mpeekc(&mp);
	if (asn1_get_tag(c) == ASN1_TAG_CONTEXT_SPECIFIC_0) {
		if (asn1_load(&mp, &cert->version) != 0) {
			fprintf(stderr, "Error: Unable to load version\n");
			return -1;
		}
	} else {
		/* version absent: defaults to v1 */
		cert->version.tag = 0;
		cert->version.value = NULL;
		cert->version.length = 0;
	}

	if (asn1_load(&mp, &cert->serial_number) != 0) {
		fprintf(stderr, "Error: Unable to load serial_number\n");
		return -1;
	}

	if (asn1_load(&mp, &cert->signature) != 0) {
		fprintf(stderr, "Error: Unable to load signature\n");
		return -1;
	}

	if (asn1_load(&mp, &cert->issuer) != 0) {
		fprintf(stderr, "Error: Unable to load issuer\n");
		return -1;
	}

	if (asn1_load(&mp, &cert->validity) != 0) {
		fprintf(stderr, "Error: Unable to load validity\n");
		return -1;
	}

	if (asn1_load(&mp, &cert->subject) != 0) {
		fprintf(stderr, "Error: Unable to load subject\n");
		return -1;
	}

	if (asn1_load(&mp, &cert->subject_public_key_info) != 0) {
		fprintf(stderr,
			"Error: Unable to load subject_public_key_info\n");
		return -1;
	}

	/* issuer_unique_id and subject_unique_id are not supported yet */

	enum X509_VERSION version = X509_VERSION_V1;
	if (X509_get_version(cert, &version) != 0) {
		fprintf(stderr, "Error: Unable to get version\n");
		return -1;
	}

	c = mpeekc(&mp);
	if (version > X509_VERSION_V1 &&
	    asn1_get_tag(c) == ASN1_TAG_CONTEXT_SPECIFIC_1) {
		fprintf(stderr,
			"Error: issuer_unique_id is not supported yet\n");
		return -1;
	}
	if (version > X509_VERSION_V1 &&
	    asn1_get_tag(c) == ASN1_TAG_CONTEXT_SPECIFIC_2) {
		fprintf(stderr,
			"Error: subject_unique_id is not supported yet\n");
		return -1;
	}

	/* extension is not available to V1 */
	if (version != X509_VERSION_V1 && mtell(&mp) < end) {
		/* 
		 * extensions [3] Extensions OPTIONAL]]
		 */
		int c = mgetc(&mp);
		if (asn1_get_tag(c) != ASN1_TAG_CONTEXT_SPECIFIC_3) {
			fprintf(stderr,
				"Error: Extensions do not start with [3]\n");
			return -1;
		}
		asn1_get_length(&mp); /* Advance to value */

		if (asn1_load_tag(&mp, &cert->extensions, ASN1_TAG_SEQUENCE) !=
		    0) {
			fprintf(stderr, "Error: Unable to load extensions\n");
			return -1;
		}
	}

	/* Check for completion */
	long current = mtell(&mp);
	memfp_close(&mp); /* It does not matter, match memfp_open */
	if (current != end) {
		fprintf(stderr, "Error: TBSCertificate length mismatch\n");
		return -1;
	}

	return 0;
}

int X509_get_version(const X509Certificate *cert, enum X509_VERSION *version)
{
	int result = 0;

	/*
	 * version	[0]	Version DEFAULT v1,
	 * 
	 * Version ::= INTEGER {v1(0), v2(1), v3(2)} 
	 */
	if (asn1_get_tag(cert->version.tag) == ASN1_TAG_CONTEXT_SPECIFIC_0) {
		/* If it is explicitly tagged, the actual version INTEGER is inside */
		if (asn1_is_constructed(cert->version.tag)) {
			/* The version is inside the constructed context-specific tag */
			const uint8_t *p = cert->version.value;
			if (asn1_get_tag(*p) == ASN1_TAG_INTEGER) {
				*version = (enum X509_VERSION)
					p[2]; /* Skip tag and length */
			}
		} else {
			/* Although it would not get here per X.509, but make no assumptions. */
			*version = (enum X509_VERSION)cert->version.value[0];
		}
	} else {
		*version = X509_VERSION_V1;
	}

	return result;
}

void X509_print_version(enum X509_VERSION version)
{
	switch (version) {
	case X509_VERSION_V1:
		printf("v1");
		break;
	case X509_VERSION_V2:
		printf("v2");
		break;
	case X509_VERSION_V3:
		printf("v3");
		break;
	default:
		printf("Unknown\n");
		break;
	}
}

void X509_print_serial_number(const ASN1Object *serial_number)
{
	/*
	 * serialNumber		SerialNumber
	 *
	 * SerialNumber ::= INTEGER
	 */

	if (asn1_get_tag(serial_number->tag) != ASN1_TAG_INTEGER) {
		fprintf(stderr, "Error: Not a valid serial number\n");
		exit(EXIT_FAILURE);
	}

	const uint8_t *p = serial_number->value;
	size_t len = serial_number->length;

	for (size_t i = 0; i < len; i++) {
		printf("%02X", p[i]);
	}
}

int X509_get_algorithm_oid(const ASN1Object *algorithm, uint32_t *oid,
			   int *oid_length)
{
	/* 
	 * signatureAlgorithm	AlgorithmIdentifier
	 *
	 * AlgorithmIdentifier ::= SEQUENCE {
	 *     algorithm OBJECT IDENTIFIER,
	 *     parameters ANY DEFINED BY algorithm OPTIONAL
	 * }
	 * 
	 * Assume rsaEncryption and NULL for parameters for now.
	 */
	if (asn1_get_tag(algorithm->tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Not a valid signatureAlgorithm\n");
		return -1;
	}

	ASN1Object obj;
	struct memfp mp;
	memfp_open(&mp, algorithm->value, algorithm->length);
	if (asn1_load_tag(&mp, &obj, ASN1_TAG_OBJECT_IDENTIFIER) != 0) {
		fprintf(stderr,
			"Error: algorithm is not a valid OBJECT IDENTIFIER\n");
		return -1;
	}
	if (asn1_get_oid(obj.value, obj.length, oid, oid_length) != 0) {
		fprintf(stderr, "Error: OID too long\n");
		return -1;
	}

	memfp_close(&mp); /* It does not matter, just clear the memory */

	return 0;
}

void X509_print_AlgorithmIdentifier(const ASN1Object *alg_id)
{
	if (asn1_get_tag(alg_id->tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr,
			"Error: Expected SEQUENCE for AlgorithmIdentifier\n");
		exit(EXIT_FAILURE);
	}

	struct memfp mp;
	memfp_open(&mp, alg_id->value, alg_id->length);

	ASN1Object obj;
	if (asn1_load_tag(&mp, &obj, ASN1_TAG_OBJECT_IDENTIFIER) == 0) {
		asn1_print_oid(&obj);
	} else {
		fprintf(stderr,
			"Error: Expected OBJECT IDENTIFIER for AlgorithmIdentifier\n");
		exit(EXIT_FAILURE);
	}

	/* Assume NULL for the parameters */
	memfp_close(&mp);
}

static void X509_print_oid_label(int oid_type)
{
	switch (oid_type) {
	case OID_TYPES_jurisdictionOfIncorporationCountryName:
		printf("jC");
		break;
	case OID_TYPES_jurisdictionOfIncorporationStateOrProvinceName:
		printf("jST");
		break;
	case OID_TYPES_jurisdictionOfIncorporationLocalityName:
		printf("jL");
		break;
	case OID_TYPES_id_at_commonName:
		printf("CN");
		break;
	case OID_TYPES_id_at_countryName:
		printf("C");
		break;
	case OID_TYPES_id_at_localityName:
		printf("L");
		break;
	case OID_TYPES_id_at_stateOrProvinceName:
		printf("ST");
		break;
	case OID_TYPES_id_at_organizationName:
		printf("O");
		break;
	case OID_TYPES_id_at_organizationalUnitName:
		printf("OU");
		break;
	case OID_TYPES_domain_validated:
		printf("DV");
		break;
	case OID_TYPES_pkcs_9_ub_emailAddress:
		printf("E");
		break;
	case OID_TYPES_pkcs_9_ub_unstructuredName:
		printf("UN");
		break;
	case OID_TYPES_pkcs_9_at_challengePassword:
		printf("CP");
		break;
	case OID_TYPES_pkcs_9_at_extensionRequest:
		printf("ER");
		break;
	case OID_TYPES_id_at_businessCategory:
		printf("BC");
		break;
	case OID_TYPES_id_at_organizationIdentifier:
		printf("OI");
		break;
	case OID_TYPES_id_at_serialNumber:
		printf("SN");
		break;
	default:
		printf("Unknown");
		break;
	}
}

void X509_print_attribute_type_and_value(const ASN1Object *att_value_obj)
{
	/* 
	 * AttributeTypeAndValue ::= SEQUENCE {
	 *     type  AttributeType,
	 *     value AttributeValue
	 * }
	 * 
	 * AttributeType ::= OBJECT IDENTIFIER
	 * AttributeValue ::= ANY -- DEFINED BY AttributeType
	 */
	/* TBD: accommodate IMPLICIT tagging */
	if (asn1_get_tag(att_value_obj->tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Not a valid AttributeTypeAndValue\n");
		exit(EXIT_FAILURE);
	}

	struct memfp mp;
	memfp_open(&mp, att_value_obj->value, att_value_obj->length);

	ASN1Object obj;
	if (asn1_load_tag(&mp, &obj, ASN1_TAG_OBJECT_IDENTIFIER) != 0) {
		fprintf(stderr, "Error: Not a valid AttributeType\n");
		exit(EXIT_FAILURE);
	}

	uint32_t oid[OID_MAX_LEN];
	int oid_length = OID_MAX_LEN;
	if (asn1_get_oid(obj.value, obj.length, oid, &oid_length) != 0) {
		fprintf(stderr, "Error: OID too long\n");
		exit(EXIT_FAILURE);
	}
	int oid_type = lookup_oid(oid, oid_length);
	if (oid_type != OID_TYPES_UNKNOWN) {
		X509_print_oid_label(oid_type);
	} else {
		print_oid(oid, oid_length);
	}

	printf("=");

	if (asn1_load(&mp, &obj) != 0) {
		fprintf(stderr, "Error: Not a valid AttributeValue\n");
		exit(EXIT_FAILURE);
	}
	int c = asn1_get_tag(obj.tag);
	switch (c) {
	case ASN1_TAG_PRINTABLE_STRING:
	case ASN1_TAG_UTF8_STRING:
	case ASN1_TAG_IA5_STRING:
	case ASN1_TAG_T61_STRING:
		asn1_print_printable_string(&obj);
		break;
	default:
		fprintf(stderr, "Error: Not a supported AttributeValue: %d\n",
			c);
	}

	memfp_close(&mp); /* It does not matter, just clear the memory */
}

void X509_print_name(const ASN1Object *name)
{
	/* 
	 * Name ::= CHOICE { -- only one possibility for now --
	 *     rdnSequence  RDNSequence
	 * }
	 * 
	 * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
	 */
	if (asn1_get_tag(name->tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Not a valid Name\n");
		exit(EXIT_FAILURE);
	}
	if (name->length == 0) {
		fprintf(stderr, "Error: Empty Name\n");
		exit(EXIT_FAILURE);
	}

	struct memfp mp;
	memfp_open(&mp, name->value, name->length);
	size_t name_length = name->length;

	/*
	 * RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue 
	 */
	while (name_length) {
		int offset1 = mtell(&mp);

		ASN1Object obj;
		int c = mgetc(&mp);
		if (asn1_get_tag(c) != ASN1_TAG_SET) {
			fprintf(stderr,
				"Error: Not a valid RelativeDistinguishedName\n");
			exit(EXIT_FAILURE);
		}
		asn1_get_length(&mp); /* Advance to value */

		if (asn1_load(&mp, &obj) != 0) {
			fprintf(stderr,
				"Error: Not a valid RelativeDistinguishedName\n");
			exit(EXIT_FAILURE);
		}
		X509_print_attribute_type_and_value(&obj);
		name_length -= (mtell(&mp) - offset1);
		if (name_length > 0) {
			printf(", ");
		}
	}

	memfp_close(&mp); /* Just clear the memory */
}

void X509_dump8(const uint8_t *buf, size_t len)
{
	/* 16 bytes / row, blank between two bytes */
	for (size_t i = 0; i < len; i++) {
		printf("%02X", buf[i]);
		if ((i + 1) % 16 == 0) {
			printf("\n");
		} else {
			printf(" ");
		}
	}
}

void X509_print_signature(const ASN1Object *signature)
{
	if (asn1_get_tag(signature->tag) != ASN1_TAG_BIT_STRING) {
		fprintf(stderr, "Error: Not a valid signature\n");
		exit(EXIT_FAILURE);
	}

	/* Skip the unused bits byte */
	const uint8_t *p = signature->value;
	size_t l = signature->length;
	if (l > 0) {
		++p;
		--l;
	}
	X509_dump8(p, l);
}

void X509_print_public_key(const ASN1Object *public_key)
{
	/* PKCS #1
	RSAPublicKey ::= SEQUENCE {
		modulus           INTEGER,  -- n
		publicExponent    INTEGER   -- e
	}
	*/
	if (asn1_get_tag(public_key->tag) != ASN1_TAG_BIT_STRING) {
		fprintf(stderr, "Error: Not a valid public key\n");
		exit(EXIT_FAILURE);
	}

	struct memfp mp;
	memfp_open(&mp, public_key->value, public_key->length);

	mgetc(&mp); /* Skip unused bits byte */
	if (asn1_get_tag(mgetc(&mp)) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Not a valid RSAPublicKey\n");
		exit(EXIT_FAILURE);
	}
	asn1_get_length(&mp); /* Advance */

	ASN1Object obj;
	if (asn1_load_tag(&mp, &obj, ASN1_TAG_INTEGER) != 0) {
		fprintf(stderr, "Error: Unable to load modulus\n");
		exit(EXIT_FAILURE);
	}
	printf("Modulus:\n");
	asn1_print_integer(&obj);
	printf("\n");

	if (asn1_load_tag(&mp, &obj, ASN1_TAG_INTEGER) != 0) {
		fprintf(stderr, "Error: Unable to load publicExponent\n");
		exit(EXIT_FAILURE);
	}
	printf("Exponent: ");
	asn1_print_integer(&obj);

	memfp_close(&mp); /* Just match memfp_open */
}

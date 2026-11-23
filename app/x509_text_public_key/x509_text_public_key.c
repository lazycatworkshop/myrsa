/* x509_text_public_key.c - This program takes in a public key certificate in
 * DER format and displays its content in text.
 * 
 * It assumes the certificate is valid in X.509 format.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <errno.h>
#include <locale.h>
#include "oid.h"
#include "x509.h"

static int X509_print_certificate(const X509Certificate *cert);

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
	if (asn1_get_tag(getc(fp)) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Not a valid X.509 certificate\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	rewind(fp);

	/* Read in the certificate*/
	static X509Certificate cert;
	size_t l = fread(cert.asn1_buf, 1, X509_CERTIFICATE_MAX_SIZE, fp);
	if (l == 0) {
		fprintf(stderr, "Error: Unable to read certificate\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	cert.cert_len = l;

	if (process_x509_certificate(&cert) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (X509_process_TBSCertificate(&cert) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (X509_print_certificate(&cert) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

out:
	if (fp)
		fclose(fp);
	return ret;
}

static int is_little_endian(void)
{
	union {
		uint32_t i;
		char c[4];
	} test_union = { 0x01020304 };

	return test_union.c[0] == 4;
}

static void X509_print_validity(const ASN1Object *validity)
{
	/* 
	Validity ::= SEQUENCE {
		notBefore Time,
		notAfter Time,
	... }	
	*/
	if (asn1_get_tag(validity->tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Not a valid validity\n");
		return;
	}

	struct memfp mp;
	memfp_open(&mp, validity->value, validity->length);
	mseek(&mp, 0, SEEK_SET);

	/* 
	Time ::= CHOICE {
		utcTime UTCTime,
		generalizedTime GeneralizedTime }	
	*/
	ASN1Object obj;
	if (asn1_load(&mp, &obj) != 0) {
		fprintf(stderr, "Error: Unable to load notBefore\n");
		return;
	}
	printf("      Not Before: ");
	asn1_print_time_string(&obj);

	printf("\n");
	if (asn1_load(&mp, &obj) != 0) {
		fprintf(stderr, "Error: Unable to load notAfter\n");
		return;
	}
	printf("      Not After : ");
	asn1_print_time_string(&obj);
	printf("\n");
}

static void
X509_print_SubjectPublicKeyInfo(const ASN1Object *subject_public_key_info)
{
	/* 
	 * SubjectPublicKeyInfo ::= SEQUENCE {
	 * algorithm AlgorithmIdentifier{{SupportedAlgorithms}},
	 * subjectPublicKey BIT STRING,
	 * ... }	
	 */
	if (asn1_get_tag(subject_public_key_info->tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Not a valid SubjectPublicKeyInfo\n");
		exit(EXIT_FAILURE);
	}

	struct memfp mp;
	memfp_open(&mp, subject_public_key_info->value,
		   subject_public_key_info->length);

	/*
	RFC 8410

	AlgorithmIdentifier  ::=  SEQUENCE  {
       		algorithm   OBJECT IDENTIFIER,
       		parameters  ANY DEFINED BY algorithm OPTIONAL
   	}
	*/
	ASN1Object obj;
	if (asn1_load_tag(&mp, &obj, ASN1_TAG_SEQUENCE) != 0) {
		fprintf(stderr, "Error: Unable to load algorithm\n");
		exit(EXIT_FAILURE);
	}
	printf("      Algorithm: ");
	X509_print_AlgorithmIdentifier(&obj);
	printf("\n");

	printf("      Subject Public Key:\n");

	if (asn1_load_tag(&mp, &obj, ASN1_TAG_BIT_STRING) != 0) {
		fprintf(stderr, "Error: Unable to load subjectPublicKey\n");
		exit(EXIT_FAILURE);
	}
	X509_print_public_key(&obj);

	memfp_close(&mp); /* Match memfp_open. Just clear the memory */
}

static void X509_print_keyusage_desc(int index)
{
	switch (index) {
	case 0:
		printf("digitalSignature");
		break;
	case 1:
		printf("nonRepudiation");
		break;
	case 2:
		printf("keyEncipherment");
		break;
	case 3:
		printf("dataEncipherment");
		break;
	case 4:
		printf("keyAgreement");
		break;
	case 5:
		printf("keyCertSign");
		break;
	case 6:
		printf("cRLSign");
		break;
	case 7:
		printf("encipherOnly");
		break;
	case 8:
		printf("decipherOnly");
		break;
	default:
		printf("Unknown");
		break;
	}
}

static void X509_print_keyusage(const ASN1Object *extension)
{
	/* 
	 * KeyUsage ::= BIT STRING {
	 *     digitalSignature        (0),
	 *     nonRepudiation          (1),
	 *     keyEncipherment         (2),
	 *     dataEncipherment        (3),
	 *     keyAgreement            (4),
	 *     keyCertSign             (5),
	 *     cRLSign                 (6),
	 *     encipherOnly            (7),
	 *     decipherOnly            (8)
	 * }
	 */
	if (asn1_get_tag(extension->tag) != ASN1_TAG_BIT_STRING) {
		fprintf(stderr, "Error: Not a valid KeyUsage\n");
		exit(EXIT_FAILURE);
	}
	const uint8_t *p = extension->value;
	int len = extension->length;
#if 0
	if (*p != 0) {
		fprintf(stderr, "Error: KeyUsage has unused bits\n");
		exit(EXIT_FAILURE);
	}
#endif
	++p; /* Skip unused bits byte */
	len -= 1;

	if (len == 0) {
		fprintf(stderr, "Error: KeyUsage is empty\n");
		exit(EXIT_FAILURE);
	}

	printf("  ");
	/* 0-7*/
	for (int i = 0; i < 8; i++) {
		if (*p & (1 << (7 - i))) {
			if (i) {
				printf(", ");
			}
			X509_print_keyusage_desc(i);
		}
	}
	/* 8 */
	if (len > 1 && (*p & 0x01)) {
		printf(", ");
		X509_print_keyusage_desc(8);
	}
}

static void X509_print_extended_key_usage(const ASN1Object *extension)
{
	/* 
	 * ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
	 * 
	 * KeyPurposeId ::= OBJECT IDENTIFIER
	 */
	if (asn1_get_tag(extension->tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Not a valid ExtKeyUsageSyntax\n");
		exit(EXIT_FAILURE);
	}

	struct memfp mp;
	memfp_open(&mp, extension->value, extension->length);
	int len = extension->length;

	printf("  ");

	while (len > 0) {
		long offset1 = mtell(&mp);
		ASN1Object obj;
		if (asn1_load_tag(&mp, &obj, ASN1_TAG_OBJECT_IDENTIFIER) != 0) {
			fprintf(stderr, "Error: Unable to load KeyPurposeId\n");
			exit(EXIT_FAILURE);
		}

		asn1_print_oid(&obj);

		len -= (mtell(&mp) - offset1);

		if (len > 0) {
			printf(", ");
		}
	}

	memfp_close(&mp); /* Clear the memory */
}

static void X509_print_basic_constraints(const ASN1Object *extension)
{
	/* 
	 * BasicConstraints ::= SEQUENCE {
	 *     cA                      BOOLEAN DEFAULT FALSE,
	 *     pathLenConstraint       INTEGER (0..MAX) OPTIONAL
	 * }
	 */
	if (asn1_get_tag(extension->tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Not a valid BasicConstraints\n");
		exit(EXIT_FAILURE);
	}

	printf("  ");

	if (extension->length == 0) {
		/* DEFAULT FALSE for cA and no pathLenConstraint */
		printf("cA: FALSE");
		return;
	}

	struct memfp mp;
	memfp_open(&mp, extension->value, extension->length);
	int len = extension->length;

	/* cA */
	long offset1 = mtell(&mp);
	ASN1Object obj;
	if (asn1_load_tag(&mp, &obj, ASN1_TAG_BOOLEAN) == 0) {
		if (*(obj.value)) {
			printf("cA: TRUE");
		} else {
			printf("cA: FALSE");
		}
	} else {
		fprintf(stderr, "Error: Unable to load cA\n");
		exit(EXIT_FAILURE);
	}

	len -= (mtell(&mp) - offset1);

	/* pathLenConstraint */
	if (len > 0) {
		if (asn1_load_tag(&mp, &obj, ASN1_TAG_INTEGER) == 0) {
			printf(", pathLenConstraint: ");
			X509_dump8(obj.value, obj.length);
		}
	}

	memfp_close(&mp); /* Clear the memory */
}

static void X509_print_key_identifier(const ASN1Object *extension)
{
	/* 
	 * SubjectKeyIdentifier ::= KeyIdentifier
	 * 
	 * KeyIdentifier ::= OCTET STRING
	 */
	if (asn1_get_tag(extension->tag) != ASN1_TAG_OCTET_STRING) {
		fprintf(stderr, "Error: Not a valid KeyIdentifier\n");
		exit(EXIT_FAILURE);
	}
	const uint8_t *p = extension->value;
	int len = extension->length;
	X509_dump8(p, len);
}

static void X509_print_authority_key_identifier(const ASN1Object *extension)
{
	/* 
	 * AuthorityKeyIdentifier ::= SEQUENCE {
	 *     keyIdentifier             [0] KeyIdentifier           OPTIONAL,
	 *     authorityCertIssuer       [1] GeneralNames            OPTIONAL,
	 *     authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL
	 * }
	 */
	if (asn1_get_tag(extension->tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Not a valid AuthorityKeyIdentifier\n");
		exit(EXIT_FAILURE);
	}

	struct memfp mp;
	memfp_open(&mp, extension->value, extension->length);
	int len = extension->length;

	ASN1Object obj;
	while (len > 0) {
		long offset1 = mtell(&mp);
		uint8_t tag = asn1_get_tag(mpeekc(&mp));
		switch (tag) {
		case ASN1_TAG_CONTEXT_SPECIFIC_0:
			/* KeyIdentifier ::= OCTET STRING */
			if (asn1_load(&mp, &obj) == 0) {
				X509_dump8(obj.value, obj.length);
			} else {
				fprintf(stderr,
					"Error: Unable to load KeyIdentifier\n");
				exit(EXIT_FAILURE);
			}
			break;
		case ASN1_TAG_CONTEXT_SPECIFIC_1:
			fprintf(stderr,
				"Error: authorityCertIssuer is not supported yet\n");
			exit(EXIT_FAILURE);
			break;
		case ASN1_TAG_CONTEXT_SPECIFIC_2:
			fprintf(stderr,
				"Error: authorityCertSerialNumber is not supported yet\n");
			exit(EXIT_FAILURE);
			break;
		default:
			fprintf(stderr,
				"Error: Unknown field in AuthorityKeyIdentifier\n");
			exit(EXIT_FAILURE);
		}
		len -= (mtell(&mp) - offset1);
	}

	memfp_close(&mp); /* Clear the memory */
}

static void print_printable_string(const uint8_t *str, size_t len)
{
#if 0
	for (size_t i = 0; i < len; i++) {
		if (str[i] >= 32 && str[i] <= 126) {
			putchar(str[i]);
		} else {
			printf("\\x%02X", str[i]);
		}
#else
	/* Accommodate utf-8 strings for now */
	if (len > ASN1_MAX_STRING_LENGTH) {
		fprintf(stderr, "Error: Printable string too long\n");
		exit(EXIT_FAILURE);
	}
	char s[ASN1_MAX_STRING_LENGTH + 1];
	memcpy(s, str, len);
	s[len] = '\0';
	printf("%s", s);

#endif
}

static void X509_print_general_name(const ASN1Object *general_name)
{
	/* 
	 * GeneralName ::= CHOICE {
	 *     otherName                       [0]     OtherName,
	 *     rfc822Name                      [1]     IA5String,
	 *     dNSName                         [2]     IA5String,
	 *     x400Address                     [3]     ORAddress,
	 *     directoryName                   [4]     Name,
	 *     ediPartyName                    [5]     EDIPartyName,
	 *     uniformResourceIdentifier       [6]     IA5String,
	 *     iPAddress                       [7]     OCTET STRING,
	 *     registeredID                    [8]     OBJECT IDENTIFIER
	 * }
	 * 
	 * IMPLICIT tagging is checked at the constructed bit.
	 */
	uint8_t tag = asn1_get_tag(general_name->tag);
	/* Assume IMPLICIT tagging  */
	const uint8_t *p = general_name->value;
	size_t len = general_name->length;
	ASN1Object obj;
	if (asn1_is_constructed(general_name->tag)) { /* Explicit */
		struct memfp mp;
		memfp_open(&mp, general_name->value, general_name->length);
		if (asn1_load(&mp, &obj) == 0) {
			p = obj.value;
			len = obj.length;
		} else {
			fprintf(stderr, "Error: Unable to load GeneralName\n");
			exit(EXIT_FAILURE);
		}
		memfp_close(&mp); /* Clear the memory */
	}
	switch (tag) {
	case ASN1_TAG_CONTEXT_SPECIFIC_1:
	case ASN1_TAG_CONTEXT_SPECIFIC_2:
	case ASN1_TAG_CONTEXT_SPECIFIC_6:
		print_printable_string(p, len);
		break;
	case ASN1_TAG_CONTEXT_SPECIFIC_4:
	default:
		fprintf(stderr, "Error: Not a supported GeneralName\n");
		exit(EXIT_FAILURE);
	}
}

static void X509_print_authority_info_access(const ASN1Object *extension)
{
	/* 
	 * AuthorityInfoAccessSyntax  ::=
	 *     SEQUENCE SIZE (1..MAX) OF AccessDescription
	 */
	if (asn1_get_tag(extension->tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr,
			"Error: Not a valid AuthorityInfoAccessSyntax\n");
		exit(EXIT_FAILURE);
	}

	struct memfp mp;
	memfp_open(&mp, extension->value, extension->length);
	int len = extension->length;

	while (len > 0) {
		long offset1 = mtell(&mp);
		/* 
		 * AccessDescription  ::=  SEQUENCE {
		 *     accessMethod          OBJECT IDENTIFIER,
		 *     accessLocation        GeneralName  }
		 */
		int c = mgetc(&mp);
		if (asn1_get_tag(c) != ASN1_TAG_SEQUENCE) {
			fprintf(stderr,
				"Error: Not a valid AccessDescription\n");
			exit(EXIT_FAILURE);
		}
		asn1_get_length(&mp);

		ASN1Object obj;

		if (asn1_load_tag(&mp, &obj, ASN1_TAG_OBJECT_IDENTIFIER) != 0) {
			fprintf(stderr, "Error: Unable to load accessMethod\n");
			exit(EXIT_FAILURE);
		}
		printf("  ");
		asn1_print_oid(&obj);

		printf(": ");

		/* accessLocation */
		if (asn1_load(&mp, &obj) != 0) {
			fprintf(stderr,
				"Error: Unable to load accessLocation\n");
			exit(EXIT_FAILURE);
		}
		X509_print_general_name(&obj);

		len -= (mtell(&mp) - offset1);
		if (len > 0) {
			printf("\n");
		}
	}

	memfp_close(&mp); /* Clear the memory */
}

static void X509_print_subject_alt_name(const ASN1Object *name)
{
	/* 
	 * SubjectAltName ::= GeneralNames
	 * 
	 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	 */
	if (asn1_get_tag(name->tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Not a valid SubjectAltName\n");
		exit(EXIT_FAILURE);
	}

	struct memfp mp;
	memfp_open(&mp, name->value, name->length);
	int len = name->length;

	while (len > 0) {
		long offset = mtell(&mp);
		ASN1Object obj;
		if (asn1_load(&mp, &obj) != 0) {
			fprintf(stderr, "Error: Unable to load GeneralName\n");
			exit(EXIT_FAILURE);
		}
		printf("  ");
		X509_print_general_name(&obj);

		len -= (mtell(&mp) - offset);
		if (len > 0) {
			printf("\n");
		}
	}
	memfp_close(&mp); /* Clear the memory */
}

static void
X509_print_policy_qualifier_info(const ASN1Object *policy_qualifier_info)
{
	/* 
	 * PolicyQualifierInfo ::= SEQUENCE {
	 *     policyQualifierId  PolicyQualifierId,
	 *     qualifier          ANY DEFINED BY policyQualifierId OPTIONAL
	 * }
	 * 
	 * PolicyQualifierId ::= OBJECT IDENTIFIER
	 */
	if (asn1_get_tag(policy_qualifier_info->tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Not a valid PolicyQualifierInfo\n");
		exit(EXIT_FAILURE);
	}

	struct memfp mp;
	memfp_open(&mp, policy_qualifier_info->value,
		   policy_qualifier_info->length);
	ASN1Object obj;
	if (asn1_load(&mp, &obj) != 0) {
		fprintf(stderr, "Error: Unable to load policyQualifierId\n");
		exit(EXIT_FAILURE);
	}
	printf("  ");
	asn1_print_oid(&obj);

	/* -> qualifier or end */
	if ((size_t)mtell(&mp) < policy_qualifier_info->length) {
		if (asn1_load(&mp, &obj) != 0) {
			fprintf(stderr, "Error: Unable to load qualifier\n");
			exit(EXIT_FAILURE);
		}
		printf(": ");

		switch (asn1_get_tag(obj.tag)) {
		case ASN1_TAG_IA5_STRING:
			asn1_print_printable_string(&obj);
			break;
		default:
			printf("tag %d\n", asn1_get_tag(obj.tag));
			X509_dump8(obj.value, obj.length);
			break;
		}
	}
	memfp_close(&mp); /* Clear the memory */
}

static void X509_print_policy_information(const ASN1Object *policy_info)
{
	/* 
	 * PolicyInformation ::= SEQUENCE {
	 *     policyIdentifier   CertPolicyId,
	 *     policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL
	 * }
	 * 
	 * CertPolicyId ::= OBJECT IDENTIFIER
	 */
	if (asn1_get_tag(policy_info->tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Not a valid PolicyInformation\n");
		exit(EXIT_FAILURE);
	}

	struct memfp mp;
	memfp_open(&mp, policy_info->value, policy_info->length);

	/* policyIdentifier */
	ASN1Object obj;
	if (asn1_load_tag(&mp, &obj, ASN1_TAG_OBJECT_IDENTIFIER) != 0) {
		fprintf(stderr, "Error: Unable to load policyIdentifier\n");
		exit(EXIT_FAILURE);
	}
	printf("  ");
	asn1_print_oid(&obj);

	/* policyQualifiers */
	/* -> policyQualifiers or end */
	if ((size_t)mtell(&mp) < policy_info->length) {
		if (asn1_load_tag(&mp, &obj, ASN1_TAG_SEQUENCE) != 0) {
			fprintf(stderr,
				"Error: Unable to load policyQualifiers\n");
			exit(EXIT_FAILURE);
		}
		printf("\n");
	}

	/* 
	 *	PolicyQualifierInfo ::= SEQUENCE {
	 *	policyQualifierId CERT-POLICY-QUALIFIER.&id({SupportedPolicyQualifiers}),
	 *	qualifier CERT-POLICY-QUALIFIER.&Qualifier
	 *	({SupportedPolicyQualifiers}{@policyQualifierId}) OPTIONAL,
	 *	... }
	 */

	while ((size_t)mtell(&mp) < policy_info->length) {
		if (asn1_load_tag(&mp, &obj, ASN1_TAG_SEQUENCE) != 0) {
			fprintf(stderr,
				"Error: Unable to load policyQualifiers\n");
			exit(EXIT_FAILURE);
		}
		X509_print_policy_qualifier_info(&obj);
	}

	memfp_close(&mp); /* Clear the memory */
}

static void X509_print_certificate_policies(const ASN1Object *cert_policy)
{
	/* 
	 * CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
	 */
	if (asn1_get_tag(cert_policy->tag) !=
	    ASN1_TAG_SEQUENCE) { /* SEQUENCE OF */
		fprintf(stderr, "Error: Not a valid CertificatePolicies\n");
		exit(EXIT_FAILURE);
	}

	struct memfp mp;
	memfp_open(&mp, cert_policy->value, cert_policy->length);
	int len = cert_policy->length;

	while (len > 0) {
		long offset1 = mtell(&mp);
		ASN1Object obj;
		if (asn1_load(&mp, &obj) != 0) {
			fprintf(stderr,
				"Error: Unable to load PolicyInformation\n");
			exit(EXIT_FAILURE);
		}
		X509_print_policy_information(&obj);
		len -= mtell(&mp) - offset1;
		if (len > 0) {
			printf("\n");
		}
	}
	memfp_close(&mp); /* Clear the memory */
}

static void
X509_print_distribution_point_name(const ASN1Object *distribution_point_name)
{
	/* 
	 * DistributionPointName ::= CHOICE {
	 *     fullName                [0]     GeneralNames,
	 *     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName
	 * }
	 */
	uint8_t tag = asn1_get_tag(distribution_point_name->tag);
	if (!asn1_is_constructed(distribution_point_name->tag)) { /* Implicit */
		fprintf(stderr, "Error: DistributionPointName is implicit\n");
		exit(EXIT_FAILURE);
	}

	struct memfp mp;
	memfp_open(&mp, distribution_point_name->value,
		   distribution_point_name->length);

	ASN1Object distribution_point_name_value;
	if (asn1_load(&mp, &distribution_point_name_value) != 0) {
		fprintf(stderr,
			"Error: Unable to load DistributionPointName value\n");
		exit(EXIT_FAILURE);
	}

	switch (tag) {
	case ASN1_TAG_CONTEXT_SPECIFIC_0:
		X509_print_general_name(&distribution_point_name_value);
		break;
	case ASN1_TAG_CONTEXT_SPECIFIC_1:
		X509_print_name(&distribution_point_name_value);
		break;
	default:
		fprintf(stderr,
			"Error: Unknown field in DistributionPointName\n");
		exit(EXIT_FAILURE);
	}

	memfp_close(&mp); /* Clear the memory */
}

static void X509_print_reason_flags(const ASN1Object *reason_flags)
{
	/* 
	 * ReasonFlags ::= BIT STRING {
	 *     unused                  (0),
	 *     keyCompromise           (1),
	 *     cACompromise            (2),
	 *     affiliationChanged      (3),
	 *     superseded              (4),
	 *     cessationOfOperation    (5),
	 *     certificateHold         (6),
	 *     privilegeWithdrawn      (7),
	 *     aACompromise            (8)
	 * }
	 */
	if (asn1_get_tag(reason_flags->tag) != ASN1_TAG_BIT_STRING) {
		fprintf(stderr, "Error: Not a valid ReasonFlags\n");
		exit(EXIT_FAILURE);
	}
	const uint8_t *p = reason_flags->value;
	int len = reason_flags->length;
	if (*p != 0) {
		fprintf(stderr, "Error: ReasonFlags has unused bits\n");
		exit(EXIT_FAILURE);
	}
	++p; /* Skip unused bits byte */

	for (int i = 0; i < (len - 1) * 8; ++i) {
		if (*p & (1 << (7 - (i % 8)))) {
			if (i) {
				printf(", ");
			}
			switch (i) {
			case 0:
				printf("unused");
				break;
			case 1:
				printf("keyCompromise");
				break;
			case 2:
				printf("cACompromise");
				break;
			case 3:
				printf("affiliationChanged");
				break;
			case 4:
				printf("superseded");
				break;
			case 5:
				printf("cessationOfOperation");
				break;
			case 6:
				printf("certificateHold");
				break;
			case 7:
				printf("privilegeWithdrawn");
				break;
			case 8:
				printf("aACompromise");
				break;
			default:
				fprintf(stderr,
					"Error: Unknown ReasonFlags bit\n");
				exit(EXIT_FAILURE);
			}
		}
	}
}

static void X509_print_distribution_point(const ASN1Object *distribution_point)
{
	/* 
	 * DistributionPoint ::= SEQUENCE {
	 *     distributionPoint       [0]     DistributionPointName OPTIONAL,
	 *     reasons                 [1]     ReasonFlags OPTIONAL,
	 *     cRLIssuer               [2]     GeneralNames OPTIONAL
	 * }
	 */
	if (asn1_get_tag(distribution_point->tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Not a valid DistributionPoint\n");
		exit(EXIT_FAILURE);
	}

	/* Each optional field */
	struct memfp mp;
	memfp_open(&mp, distribution_point->value, distribution_point->length);
	int len = distribution_point->length;
	ASN1Object obj;
	while (len > 0) {
		long start_offset = mtell(&mp);
		int c = mgetc(&mp);
		if (asn1_is_constructed(c) == 0) {
			fprintf(stderr,
				"Error: DistributionPoint expected EXPLICIT\n");
			exit(EXIT_FAILURE);
		}
		asn1_get_length(&mp);

		printf("  ");

		uint8_t tag = asn1_get_tag(c);
		switch (tag) {
		case ASN1_TAG_CONTEXT_SPECIFIC_0:
			if (asn1_load(&mp, &obj) != 0) {
				fprintf(stderr,
					"Error: Unable to load DistributionPointName\n");
				exit(EXIT_FAILURE);
			}
			X509_print_distribution_point_name(&obj);
			break;
		case ASN1_TAG_CONTEXT_SPECIFIC_1:
			if (asn1_load(&mp, &obj) != 0) {
				fprintf(stderr,
					"Error: Unable to load ReasonFlags\n");
				exit(EXIT_FAILURE);
			}
			X509_print_reason_flags(&obj);
			break;
		case ASN1_TAG_CONTEXT_SPECIFIC_2:
			if (asn1_load(&mp, &obj) != 0) {
				fprintf(stderr,
					"Error: Unable to load CRLIssuer\n");
				exit(EXIT_FAILURE);
			}
			X509_print_general_name(&obj);
			break;
		default:
			fprintf(stderr,
				"Error: Unknown field in DistributionPoint\n");
			exit(EXIT_FAILURE);
		}
		len -= mtell(&mp) - start_offset;
		if (len > 0) {
			printf("\n");
		}
	}
	memfp_close(&mp); /* Clear the memory */
}

static void X509_print_crl_distribution_points(const ASN1Object *extension)
{
	/* 
	 * CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
	 */
	if (asn1_get_tag(extension->tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Not a valid CRLDistributionPoints\n");
		exit(EXIT_FAILURE);
	}

	struct memfp mp;
	memfp_open(&mp, extension->value, extension->length);
	int len = extension->length;

	while (len > 0) {
		long start_offset = mtell(&mp);
		ASN1Object distribution_point;
		if (asn1_load(&mp, &distribution_point) != 0) {
			fprintf(stderr,
				"Error: Unable to load DistributionPoint\n");
			exit(EXIT_FAILURE);
		}
		X509_print_distribution_point(&distribution_point);
		len -= mtell(&mp) - start_offset;
		if (len > 0) {
			printf("\n");
		}
	}
	memfp_close(&mp); /* Clear the memory */
}

static uint64_t endian_swap64(uint64_t x)
{
	return ((x & 0x00000000000000FFULL) << 56) |
	       ((x & 0x000000000000FF00ULL) << 40) |
	       ((x & 0x0000000000FF0000ULL) << 24) |
	       ((x & 0x00000000FF000000ULL) << 8) |
	       ((x & 0x000000FF00000000ULL) >> 8) |
	       ((x & 0x0000FF0000000000ULL) >> 24) |
	       ((x & 0x00FF000000000000ULL) >> 40) |
	       ((x & 0xFF00000000000000ULL) >> 56);
}

static uint16_t endian_swap16(uint16_t x)
{
	return ((x & 0x00FF) << 8) | ((x & 0xFF00) >> 8);
}

/* RFC 5246
 * enum {
 *	none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
 *	sha512(6), (255)
 * } HashAlgorithm;
*/
enum hash_alg {
	HASH_ALG_NONE = 0,
	HASH_ALG_MD5 = 1,
	HASH_ALG_SHA1 = 2,
	HASH_ALG_SHA224 = 3,
	HASH_ALG_SHA256 = 4,
	HASH_ALG_SHA384 = 5,
	HASH_ALG_SHA512 = 6,
	HASH_ALG_MAX
};

static const char *const hash_alg_str[HASH_ALG_MAX] = {
	"None", "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"
};

/* RFC 5246
 * enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
 * SignatureAlgorithm;
 */
enum sig_alg {
	SIG_ALG_ANONYMOUS = 0,
	SIG_ALG_RSA = 1,
	SIG_ALG_DSA = 2,
	SIG_ALG_ECDSA = 3,
	SIG_ALG_MAX
};

/* RFC 5246
 * enum {
 *	anonymous(0), rsa(1), dsa(2), ecdsa(3), (255)
 * } SignatureAlgorithm;
 */
static const char *const sig_alg_str[SIG_ALG_MAX] = {
	"Anonymous",
	"RSA",
	"DSA",
	"ECDSA",
};

#define CT_V1_HASH_LENGTH 32 /* SHA-256 */

#pragma pack(push, 1)
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
#pragma pack(pop)

static struct tm X509_get_sct_timestamp(uint64_t timestamp_ms)
{
	time_t timestamp_sec = (is_little_endian() ?
					endian_swap64(timestamp_ms) :
					timestamp_ms) /
			       1000;
	struct tm *tm;
	tm = gmtime(&timestamp_sec);
	return *tm;
}

static void X509_print_sct(const uint8_t *sct, int sct_len)
{
	/* 
	 * struct {
	 *	Version sct_version;
	 * 	LogID id;
	 * 	uint64 timestamp;
	 * 	CtExtensions extensions;
	 *	digitally-signed struct {
	 *		Version sct_version;
	 *		SignatureType signature_type = certificate_timestamp;
	 *		uint64 timestamp;
	 *		LogEntryType entry_type;
	 *		select(entry_type) {
	 *			case x509_entry: ASN.1Cert;
	 *			case precert_entry: PreCert;
	 *		} signed_entry;
	 *		CtExtensions extensions;
	 *	};
	 *} SignedCertificateTimestamp;
	 * 
	 * 
	 * RFC 5246
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

	const struct sct_header *p = (const struct sct_header *)sct;
	printf("    version: v%d\n", p->version + 1);
	if (p->version == 0) {
		printf("    log_id:\n");
		X509_dump8(p->log_id, CT_V1_HASH_LENGTH);

		struct tm tm = X509_get_sct_timestamp(p->timestamp);
		printf("    timestamp: %s\n", asctime(&tm));

		if (p->extensions_length == 0) {
			printf("    extensions: none\n");
		} else {
			printf("    extensions:\n");
			X509_dump8(sct + sizeof(struct sct_header),
				   endian_swap16(p->extensions_length));
		}

		const struct sct_signature_header *sig =
			(const struct sct_signature_header
				 *)(sct + sizeof(struct sct_header) +
				    endian_swap16(p->extensions_length));
		printf("    signature:\n");
		printf("      hash_alg: %s\n", hash_alg_str[sig->hash_alg]);
		printf("      sig_alg: %s\n", sig_alg_str[sig->sig_alg]);
		uint16_t sig_len = endian_swap16(sig->sig_len);
		printf("      sig_len: %d\n", sig_len);
		X509_dump8(sct + sizeof(struct sct_header) +
				   sizeof(struct sct_signature_header),
			   sig_len);

	} else {
		/* higher versions: TBD */
		printf("\n");
		X509_dump8(sct, sct_len);
	}
}

static void X509_print_scts(const ASN1Object *extension)
{
	/* 
	 * SCTs ::= OCTET STRING
	 */
	if (asn1_get_tag(extension->tag) != ASN1_TAG_OCTET_STRING) {
		fprintf(stderr, "Error: Not a valid SCTs\n");
		exit(EXIT_FAILURE);
	}
	const uint8_t *p = extension->value;
	/* Two bytes-prefix of TLS encoding */
	int len = *p << 8 | *(p + 1);
	++p; /* Skip first byte of length */
	++p; /* Skip second byte of length */

	while (len > 0) {
		const uint8_t *start_p = p;
		int sct_length = *p << 8 | *(p + 1);
		++p; /* Skip first byte of length */
		++p; /* Skip second byte of length */

		printf("  SCT:\n");
		X509_print_sct(p, sct_length);
		p += sct_length; /* -> next SCT or end */

		const uint8_t *end_p = p;
		len -= (end_p - start_p);
		if (len > 0) {
			printf("\n");
		}
	}

	if (len < 0) {
		fprintf(stderr, "Error: SCTs length mismatch\n");
		exit(EXIT_FAILURE);
	}
}

static void X509_print_extension(const ASN1Object *extension)
{
	/* 
	 * Extension ::= SEQUENCE {
	 *     extnID      OBJECT IDENTIFIER,
	 *     critical    BOOLEAN DEFAULT FALSE,
	 *     extnValue   OCTET STRING
	 * }
	 */
	if (asn1_get_tag(extension->tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Not a valid Extension\n");
		exit(EXIT_FAILURE);
	}

	struct memfp mp;
	memfp_open(&mp, extension->value, extension->length);
	ASN1Object obj;
	if (asn1_load_tag(&mp, &obj, ASN1_TAG_OBJECT_IDENTIFIER) != 0) {
		fprintf(stderr, "Error: Unable to load extnID\n");
		exit(EXIT_FAILURE);
	}

	int oid_type = asn1_get_oid_type(&obj);
	asn1_print_oid(&obj);

	/* Optional critical field */
	int c = mpeekc(&mp);
	if (asn1_get_tag(c) == ASN1_TAG_BOOLEAN) {
		if (asn1_load_tag(&mp, &obj, ASN1_TAG_BOOLEAN) == 0) {
			if (asn1_is_true(obj.value[0])) {
				printf(", critical");
			}
		}
	}

	printf("\n");

	/* extValue */
	c = mgetc(&mp);
	if (asn1_get_tag(c) != ASN1_TAG_OCTET_STRING) {
		fprintf(stderr, "Error: Not a valid extnValue\n");
		exit(EXIT_FAILURE);
	}
	asn1_get_length(&mp); /* Advance to value */

	if (asn1_load(&mp, &obj) != 0) {
		fprintf(stderr, "Error: Unable to load extnValue\n");
		exit(EXIT_FAILURE);
	}
	switch (oid_type) {
	case OID_TYPES_id_ce_keyUsage:
		X509_print_keyusage(&obj);
		break;
	case OID_TYPES_id_ce_extKeyUsage:
		X509_print_extended_key_usage(&obj);
		break;
	case OID_TYPES_id_ce_basicConstraints:
		X509_print_basic_constraints(&obj);
		break;
	case OID_TYPES_id_ce_subjectKeyIdentifier:
		X509_print_key_identifier(&obj);
		break;
	case OID_TYPES_id_ce_authorityKeyIdentifier:
		X509_print_authority_key_identifier(&obj);
		break;
	case OID_TYPES_id_pe_authorityInfoAccess:
		X509_print_authority_info_access(&obj);
		break;
	case OID_TYPES_id_ce_subjectAltName:
		X509_print_subject_alt_name(&obj);
		break;
	case OID_TYPES_id_ce_certificatePolicies:
		X509_print_certificate_policies(&obj);
		break;
	case OID_TYPES_id_ce_cRLDistributionPoints:
		X509_print_crl_distribution_points(&obj);
		break;
	case OID_TYPES_appleSecurity_6_86:
		if (obj.tag == ASN1_TAG_NULL) {
			break;
		}
		/* fall through */
	case OID_TYPES_embedded_scts:
		X509_print_scts(&obj);
		break;
	case OID_TYPES_id_ce_subjectDirectoryAttributes: /* TBD */
	default:
		X509_dump8(obj.value, obj.length);
		break;
	}
	printf("\n");

	memfp_close(&mp); /* Clear the memory */
}

static void X509_print_extensions(const X509Certificate *cert)
{
	/* 
	 * Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension 
	 */
	if (asn1_get_tag(cert->extensions.tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Not a valid Extensions\n");
		exit(EXIT_FAILURE);
	}

	struct memfp mp;
	memfp_open(&mp, cert->extensions.value, cert->extensions.length);
	int extensions_length = cert->extensions.length;

	while (extensions_length > 0) {
		long start_offset = mtell(&mp);
		ASN1Object extension;
		if (asn1_load(&mp, &extension) != 0) {
			fprintf(stderr, "Error: Unable to load extension\n");
			exit(EXIT_FAILURE);
		}
		X509_print_extension(&extension);

		extensions_length -= mtell(&mp) - start_offset;
	}

	memfp_close(&mp); /* Clear the memory */
}

static int X509_print_certificate(const X509Certificate *cert)
{
	/*
AuthenticationFramework
{joint-iso-itu-t ds(5) module(1) authenticationFramework(7) 9}
DEFINITIONS ::=

- - - X.690 ASN.1 
The "TagDefault" is taken as EXPLICIT TAGS if it is "empty".

SIGNATURE ::= SEQUENCE {
	algorithmIdentifier 	AlgorithmIdentifier{{SupportedAlgorithms}},
	signature 				BIT STRING,
... }

SIGNED{ToBeSigned} ::= SEQUENCE {
toBeSigned ToBeSigned,
COMPONENTS OF SIGNATURE,
...,
[[4:
altAlgorithmIdentifier AlgorithmIdentifier{{SupportedAltAlgorithms}} OPTIONAL,
altSignature BIT STRING OPTIONAL]]
} (WITH COMPONENTS {..., altAlgorithmIdentifier PRESENT, altSignature PRESENT } |
WITH COMPONENTS {..., altAlgorithmIdentifier ABSENT, altSignature ABSENT } ) }

Certificate ::= SIGNED{TBSCertificate}
TBSCertificate ::= SEQUENCE {
	version					[0]	Version DEFAULT v1,
	serialNumber 					CertificateSerialNumber,
	signature 					AlgorithmIdentifier{{SupportedAlgorithms}},
	issuer 						Name,
	validity 						Validity,
	subject 						Name,
	subjectPublicKeyInfo 		SubjectPublicKeyInfo,
	issuerUniqueIdentifier	[1]	IMPLICIT UniqueIdentifier OPTIONAL,
	...,
	[[2: -- if present, version shall be v2 or v3
	subjectUniqueIdentifier [2] IMPLICIT UniqueIdentifier OPTIONAL]],
	[[3: -- if present, version shall be v2 or v3
	extensions [3] Extensions OPTIONAL]]

	-- If present, version shall be v3]]
}	
*/
	int ret = EXIT_SUCCESS;

	/* Display the parsed X.509 certificate information */
	printf("X.509 Certificate:\n");
	printf("  TBSCertificate:\n");

	printf("    Version: ");
	enum X509_VERSION version;
	if (X509_get_version(cert, &version) != 0) {
		fprintf(stderr, "Error: Unable to get version\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	X509_print_version(version);
	printf("\n");

	printf("    Serial Number: ");
	X509_print_serial_number(&cert->serial_number);
	printf("\n");

	printf("    Signature Algorithm: ");
	X509_print_AlgorithmIdentifier(&cert->signatureAlgorithm);
	printf("\n");

	printf("    Issuer: ");
	X509_print_name(&cert->issuer);
	printf("\n");

	printf("    Validity:\n");
	X509_print_validity(&cert->validity);

	printf("    Subject: ");
	X509_print_name(&cert->subject);
	printf("\n");

	printf("    Subject Public Key Info:\n");
	X509_print_SubjectPublicKeyInfo(&cert->subject_public_key_info);
	printf("\n");

	if (version != X509_VERSION_V1) {
		printf("    Extensions:\n");
		X509_print_extensions(cert);
	}

	printf("\n");
	printf("  Signature:\n");
	printf("    Algorithm: ");
	X509_print_AlgorithmIdentifier(&cert->signatureAlgorithm);
	printf("\n");

	printf("    Signature:\n");
	X509_print_signature(&cert->signatureValue);
	printf("\n");

out:
	return ret;
}

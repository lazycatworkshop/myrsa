/* csr_text.c - A program to display a PKCS #10 Certificate Signing Request
 * (CSR), DER encoded, in text.
 *
 *	Usage : csr_text -f <filename>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include "asn1.h"
#include "oid.h"
#include "x509.h"
#include "memfp.h"

struct CertReq {
	uint8_t buf[X509_CERTIFICATE_MAX_SIZE];
	size_t len;

	ASN1Object info;
	ASN1Object sig_alg;
	ASN1Object sig;
};

static int parse_csr(struct CertReq *csr)
{
	/*
	CertificationRequest ::= SEQUENCE {
	certificationRequestInfo CertificationRequestInfo,
	signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
	signature BIT STRING
	*/
	struct memfp mp;
	memfp_open(&mp, csr->buf, csr->len);
	mseek(&mp, 0, SEEK_SET);

	if (asn1_get_tag(mgetc(&mp)) != ASN1_TAG_SEQUENCE || mgetc(&mp) == 0) {
		fprintf(stderr, "Error: Not a valid CertificationRequest\n");
		return -1;
	}
	mseek(&mp, 0, SEEK_SET);
	mgetc(&mp);
	asn1_get_length(&mp);

	if (asn1_load(&mp, &csr->info) != 0) {
		fprintf(stderr,
			"Error: Failed to parse CertificationRequestInfo\n");
		return -1;
	}

	if (asn1_load(&mp, &csr->sig_alg) != 0) {
		fprintf(stderr, "Error: Failed to parse signatureAlgorithm\n");
		return -1;
	}

	if (asn1_load(&mp, &csr->sig) != 0) {
		fprintf(stderr, "Error: Failed to parse signature\n");
		return -1;
	}

	memfp_close(&mp);

	return 0;
}

static void print_csi(const ASN1Object *csi)
{
	struct memfp mp;
	memfp_open(&mp, csi->value, csi->length);
	mseek(&mp, 0, SEEK_SET);

	/*
	CertificationRequestInfo ::= SEQUENCE {
		version INTEGER { v1(0) } (v1,...),
		subject Name,
		subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
		attributes [0] Attributes{{ CRIAttributes }}
	}
	*/
	printf("    Version: ");
	ASN1Object obj;
	if (asn1_load_tag(&mp, &obj, ASN1_TAG_INTEGER) != 0) {
		fprintf(stderr, "Error: Failed to parse version\n");
		exit(EXIT_FAILURE);
	}
	X509_print_version(obj.value[0]);
	printf("\n");

	if (asn1_load_tag(&mp, &obj, ASN1_TAG_SEQUENCE) != 0) {
		fprintf(stderr, "Error: Failed to parse subject\n");
		exit(EXIT_FAILURE);
	}
	printf("    Subject: ");
	X509_print_name(&obj);
	printf("\n");

	/*
	SubjectPublicKeyInfo {ALGORITHM: IOSet} ::= SEQUENCE {
		algorithm AlgorithmIdentifier {{IOSet}},
		subjectPublicKey BIT STRING
	}
	*/
	printf("    Subject Public Key Info:\n");
	if (asn1_get_tag(mgetc(&mp)) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Failed to parse subjectPKInfo\n");
		exit(EXIT_FAILURE);
	}
	asn1_get_length(&mp);
	/*
	AlgorithmIdentifier {ALGORITHM:IOSet } ::= SEQUENCE {

	algorithm ALGORITHM.&id({IOSet}),
	parameters ALGORITHM.&Type({IOSet}{@algorithm}) OPTIONAL
	}
	*/
	printf("      algorithm: ");
	if (asn1_load_tag(&mp, &obj, ASN1_TAG_SEQUENCE) != 0) {
		fprintf(stderr,
			"Error: Failed to parse subjectPKInfo/algorithm\n");
		exit(EXIT_FAILURE);
	}
	X509_print_AlgorithmIdentifier(&obj);
	printf("\n");

	if (asn1_load_tag(&mp, &obj, ASN1_TAG_BIT_STRING) != 0) {
		fprintf(stderr,
			"Error: Failed to parse subjectPKInfo/subjectPublicKey\n");
		exit(EXIT_FAILURE);
	}
	X509_print_public_key(&obj);
	printf("\n");

	printf("    Attributes: ");
	int c = mgetc(&mp);
	if (asn1_get_tag(c) == (ASN1_TAG_CONTEXT_SPECIFIC_0)) {
		if (asn1_is_constructed(c)) {
#if defined(DEBUG)
			fprintf(stderr,
				"Warning: Expected IMPLICIT context-specific tag\n");
#endif
			size_t len = asn1_get_length(
				&mp); /* Advance to the content */
			if (len == 0) /* openssl does not have command
					 * line options to create attributes
					 * component and result in empty
					 * component instead of omitting it */
				printf("Empty\n");
			return;
		} else {
			mungetc(&mp); /* IMPLICIT put back the tag */
		}
		if (asn1_load(&mp, &obj) != 0) {
			fprintf(stderr, "Error: Failed to parse attributes\n");
			exit(EXIT_FAILURE);
		}

		X509_print_attribute_type_and_value(&obj);
		printf("\n");
	}
	memfp_close(&mp);
}

static void print_csr(struct CertReq *csr)
{
	printf("Certificate Request:\n");
	printf("  CertificationRequestInfo:\n");
	print_csi(&csr->info);

	printf("  Signature Algorithm: ");
	X509_print_AlgorithmIdentifier(&csr->sig_alg);
	printf("\n");

	printf("  Signature:\n");
	X509_print_signature(&csr->sig);
	printf("\n");
}

int main(int argc, char *argv[])
{
	FILE *fp = NULL;
	struct CertReq csr;
	size_t len;
	int c;
	int ret = EXIT_SUCCESS;

	while ((c = getopt(argc, argv, "f:")) != -1) {
		switch (c) {
		case 'f':
			if (fp)
				fclose(fp);
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

	len = fread(csr.buf, 1, sizeof(csr.buf), fp);
	if (len == 0) {
		fprintf(stderr, "Error: File is empty\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	csr.len = len;

	if (csr.buf[0] == '-') { /* Encapsulation Boundary in PEM */
		fprintf(stderr, "Error: File is in PEM format\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	if (len == sizeof(csr.buf) && getc(fp) != EOF) {
		fprintf(stderr, "Error: File is too large\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	if (parse_csr(&csr) == 0)
		print_csr(&csr);
	else
		ret = EXIT_FAILURE;

out:
	if (fp)
		fclose(fp);
	return ret;
}

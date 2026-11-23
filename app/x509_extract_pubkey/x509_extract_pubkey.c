/* x509_extract_pubkey.c - Extract the public key from an X.509
 * certificate and save it to a file.
 *
 * It reads only DER-encoded X.509 certificates with RSA public keys. 
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include "x509.h"

static void print_usage(const char *prog_name)
{
	fprintf(stderr,
		"Usage: %s -c <input_cert.der> -p <output_pubkey.der>\n",
		prog_name);
}

int main(int argc, char *argv[])
{
	int ret = EXIT_SUCCESS;
	const char *cert_file = NULL;
	const char *output_file = NULL;
	FILE *cert_fp = NULL;
	FILE *output_fp = NULL;
	int opt;
	while ((opt = getopt(argc, argv, "c:p:")) != -1) {
		switch (opt) {
		case 'c':
			cert_file = optarg;
			break;
		case 'p':
			output_file = optarg;
			break;
		default:
			print_usage(argv[0]);
			return EXIT_FAILURE;
		}
	}
	if (!cert_file || !output_file) {
		print_usage(argv[0]);
		ret = EXIT_FAILURE;
		goto out;
	}

	if ((cert_fp = fopen(cert_file, "rb")) == NULL) {
		fprintf(stderr, "Error: Unable to open certificate file: %s\n",
			strerror(errno));
		ret = EXIT_FAILURE;
		goto out;
	}

	/* Read in the certificate*/
	static X509Certificate cert;
	size_t l = fread(cert.asn1_buf, 1, X509_CERTIFICATE_MAX_SIZE, cert_fp);
	if (l == 0) {
		fprintf(stderr, "Error: Unable to read certificate\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	cert.cert_len = l;

	if (process_x509_certificate(&cert) != 0) {
		fprintf(stderr, "Error: Unable to process X.509 certificate\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	if (X509_process_TBSCertificate(&cert) != 0) {
		fprintf(stderr, "Error: Unable to process X.509 certificate\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	/*
	SubjectPublicKeyInfo ::= SEQUENCE {
		algorithm AlgorithmIdentifier{{SupportedAlgorithms}},
		subjectPublicKey BIT STRING,
	... }
	*/
	if (asn1_get_tag(cert.subject_public_key_info.tag) !=
	    ASN1_TAG_SEQUENCE) {
		fprintf(stderr,
			"Error: Expected SEQUENCE for subjectPublicKey\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	struct memfp mp;
	memfp_open(&mp, cert.subject_public_key_info.value,
		   cert.subject_public_key_info.length);
	mseek(&mp, 0, SEEK_SET);
	/*
	AlgorithmIdentifier{ALGORITHM:SupportedAlgorithms} ::= SEQUENCE {
	algorithm ALGORITHM.&id({SupportedAlgorithms}),
	parameters ALGORITHM.&Type({SupportedAlgorithms}{@algorithm}) OPTIONAL,
	... }

	*/
	if (asn1_load_tag(&mp, &cert.subjectPublicKeyAlgorithm,
			  ASN1_TAG_SEQUENCE) != 0) {
		fprintf(stderr,
			"Error: Expected SEQUENCE for AlgorithmIdentifier\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	if (asn1_load_tag(&mp, &cert.subjectPublicKey, ASN1_TAG_BIT_STRING) !=
	    0) {
		fprintf(stderr,
			"Error: Expected BIT STRING for subjectPublicKey\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	const uint8_t *p = cert.subjectPublicKey.value;
	l = cert.subjectPublicKey.length;
	if (l > 1 && p[0] == 0x00) {
		/* Remove unused bits */
		++p;
		--l;
	}

	output_fp = fopen(output_file, "wb");
	if (!output_fp) {
		fprintf(stderr, "Error: Unable to open output file: %s\n",
			strerror(errno));
		ret = EXIT_FAILURE;
		goto out;
	}
	if (fwrite(p, 1, l, output_fp) != l) {
		fprintf(stderr, "Error: Unable to write to output file\n");
		ret = EXIT_FAILURE;
		goto out;
	}

out:
	if (cert_fp)
		fclose(cert_fp);
	if (output_fp)
		fclose(output_fp);

	return ret;
}

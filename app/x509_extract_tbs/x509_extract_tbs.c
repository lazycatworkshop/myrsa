/* x509_extract_tbs.c - Extract the DER-encoded TBSCertificate from an X.509
 * certificate and save it to a file.
 */
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "x509.h"
#include <stdint.h>
#include "asn1.h"
#include "memfp.h"

static void print_usage(const char *prog_name)
{
	fprintf(stderr, "Usage: %s -c <input_cert.der> -t <output_tbs.der>\n",
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

	while ((opt = getopt(argc, argv, "c:t:")) != -1) {
		switch (opt) {
		case 'c':
			cert_file = optarg;
			break;
		case 't':
			output_file = optarg;
			break;
		default:
			print_usage(argv[0]);
			return EXIT_FAILURE;
		}
	}
	if (!cert_file || !output_file) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	cert_fp = fopen(cert_file, "rb");
	if (!cert_fp) {
		fprintf(stderr, "Error: Unable to open certificate file: %s\n",
			strerror(errno));
		ret = EXIT_FAILURE;
		goto out;
	}

	/* Load the certificate and check for top level structure */
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

	output_fp = fopen(output_file, "wb");
	if (!output_fp) {
		fprintf(stderr, "Error: Unable to open output file: %s\n",
			strerror(errno));
		ret = EXIT_FAILURE;
		goto out;
	}

	/* TBS is the first component */
	struct memfp mp;
	memfp_open(&mp, cert.asn1_buf, cert.cert_len);
	mgetc(&mp); /* Top level SEQUENCE tag */
	asn1_get_length(&mp); /* Top level SEQUENCE length */
	long tbs_start = mtell(&mp);
	int c = mgetc(&mp);
	if (asn1_get_tag(c) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Not a valid TBSCertificate\n");
		ret = EXIT_FAILURE;
		memfp_close(&mp);
		goto out;
	}
	size_t tbs_len = asn1_get_length(&mp);
	mseek(&mp, tbs_len, SEEK_CUR);
	size_t total_tbs_len = mtell(&mp) - tbs_start;

	if (fwrite(cert.asn1_buf + tbs_start, 1, total_tbs_len, output_fp) !=
	    total_tbs_len) {
		fprintf(stderr, "Error: Unable to write to output file\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	memfp_close(&mp);

out:
	if (cert_fp)
		fclose(cert_fp);
	if (output_fp)
		fclose(output_fp);

	return ret;
}

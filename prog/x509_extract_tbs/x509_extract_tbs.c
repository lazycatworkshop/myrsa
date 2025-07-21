/* x509_extract_tbs.c - A program to save the TBSCertificate
 * components to a separate file.
* The program takes only DER encoded certificates and assumes the validity.
*/
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#define ASN1_TAG_MASK 0xdf /* Take out P/C flag */

int asn1_get_length(FILE *fp);

int main(int argc, char *argv[])
{
	/* Take the filenames of input certificate, output public key and signature
           from the command line */
	char *cert_file = NULL;
	char *tbs_file = NULL;
	FILE *cert_fp = NULL;
	FILE *tbs_fp = NULL;
	int ret = EXIT_SUCCESS;
	int c;
	while ((c = getopt(argc, argv, "c:p:")) != -1) {
		switch (c) {
		case 'c':
			cert_file = optarg;
			break;
		case 'p':
			tbs_file = optarg;
			break;
		default:
			fprintf(stderr,
				"Usage: %s -c <cert_file> -p <tbs_file>\n",
				argv[0]);
			ret = EXIT_FAILURE;
			goto out;
		}
	}

	if (cert_file == NULL || tbs_file == NULL) {
		fprintf(stderr, "Usage: %s -c <cert_file> -p <pub_key_file>\n",
			argv[0]);
		ret = EXIT_FAILURE;
		goto out;
	}

	/* Open the input certificate file */
	cert_fp = fopen(cert_file, "r");
	if (cert_fp == NULL) {
		perror("Error: failed to open the input certificate file\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	/* Open the output public key file */
	tbs_fp = fopen(tbs_file, "w");
	if (tbs_fp == NULL) {
		perror("Error: failed to open the output public key file\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	fseek(cert_fp, 0, SEEK_SET);
	c = getc(cert_fp); /* Top most SEQUENCE */
	if (c != 0x30) {
		fprintf(stderr, "Error: Not a valid DER encoded certificate\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	size_t len = asn1_get_length(cert_fp);
	size_t start_offset = ftell(cert_fp);
#ifdef DEBUG
	printf("Length of the 1st SEQUENCE: %ld\n", len);
	printf("Start offset: %ld\n", start_offset);
#endif

	c = getc(cert_fp); /* 2nd SEQUENCE for TBSCertificate */
	size_t length_bytes = getc(cert_fp) & 0x7f;
	fseek(cert_fp, -1, SEEK_CUR);
	len = asn1_get_length(cert_fp);
#ifdef DEBUG
	printf("Length of the 2nd SEQUENCE: %ld\n", len);
#endif

	/* Write the TBSCertificate to the output file */
	fseek(cert_fp, start_offset, SEEK_SET);
	/* Total length =	1 (SEQUENCE) + 
	                  	1 (1st length octet) +
				length bytes + 
				value */
	for (int i = 0; i < 1 + 1 + length_bytes + len; i++) {
		c = getc(cert_fp);
		putc(c, tbs_fp);
	}

out:
	/* Close the input certificate file */
	if (cert_fp)
		fclose(cert_fp);
	if (tbs_fp)
		fclose(tbs_fp);

	return ret;
}

int asn1_get_length(FILE *fp)
{
	/* Length octets */
	int length = getc(fp);
	size_t length_bytes = 0;
	if (length & 0x80) {
		length_bytes = length & 0x7f;
		length = 0;
		for (int i = 0; i < length_bytes; i++) {
			length = (length << 8) | getc(fp);
		}
	}

	return length;
}
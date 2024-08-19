/** rsa_text_public_key.c - This program takes in a public key file in DER
 *  format for PKCS public keys and displays its content in text.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>

enum ASN1_TAG {

	ASN1_TAG_INTEGER = 0x02,
	ASN1_TAG_BIT_STRING = 0x03,

	/* Add more tags here */
	ASN1_TAG_UNKNOWN = 0xff
};

int asn1_find_tag(FILE *fp, uint8_t tag);
int asn1_get_length(FILE *fp);

int main(int argc, char *argv[])
{
	FILE *fp = NULL;
	int c;
	int i;
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

	printf("PKCS #1 Public Key\n");

	if (asn1_find_tag(fp, ASN1_TAG_BIT_STRING) < 0) {
		fprintf(stderr, "Error: Unable to find bitstring tag\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	if (asn1_find_tag(fp, ASN1_TAG_INTEGER) < 0) {
		fprintf(stderr,
			"Error: Unable to find integer tag (modulus)\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	printf("  Modulus:\n");
	int length = asn1_get_length(fp);
	for (i = 0; i < length; i++) {
		printf("%02x ", getc(fp));
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}
	printf("\n");

	if (asn1_find_tag(fp, ASN1_TAG_INTEGER) < 0) {
		fprintf(stderr,
			"Error: Unable to find integer tag(publicExponent)\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	printf("\n  Exponent:\n");
	length = asn1_get_length(fp);
	for (i = 0; i < length; i++) {
		printf("%02x ", getc(fp));
	}
	printf("\n");

	ret = EXIT_SUCCESS;

out:
	if (fp)
		fclose(fp);
	return ret;
}

int asn1_find_tag(FILE *fp, uint8_t tag)
{
	int c;
	while ((c = getc(fp)) != tag) {
		if (c == EOF) {
			return -1;
		}
	}
	return 0;
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
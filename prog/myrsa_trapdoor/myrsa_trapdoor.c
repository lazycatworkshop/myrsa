/** myrsa_trapdoor.c - Perform RSA trapdoor function with PKCS #1 public key
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include "myrsa.h"

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
	char *message_file = NULL;
	char *key_file = NULL;
	FILE *message_fp = NULL;
	FILE *key_fp = NULL;
	int c;
	int ret = EXIT_SUCCESS;

	while ((c = getopt(argc, argv, "m:k:")) != -1) {
		switch (c) {
		case 'm':
			message_file = optarg;
			break;
		case 'k':
			key_file = optarg;
			break;
		default:
			fprintf(stderr,
				"Usage: %s -m <message file> -k <keyfile>\n",
				argv[0]);
			ret = EXIT_FAILURE;
			goto out;
		}
	}

	if (message_file == NULL || key_file == NULL) {
		fprintf(stderr, "Usage: %s -m <message file> -k <key file>\n",
			argv[0]);
		ret = EXIT_FAILURE;
		goto out;
	}

	message_fp = fopen(message_file, "rb");
	if (message_fp == NULL) {
		fprintf(stderr, "Error: Unable to open message file\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	key_fp = fopen(key_file, "rb");
	if (key_fp == NULL) {
		fprintf(stderr, "Error: Unable to open key file\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	fseek(message_fp, 0, SEEK_END);
	long message_size = ftell(message_fp);
	fseek(message_fp, 0, SEEK_SET);
	bn message;
	message.size = message_size;
	fread(message.data, 1, message.size, message_fp);

	if (asn1_find_tag(key_fp, ASN1_TAG_BIT_STRING) < 0) {
		fprintf(stderr, "Error: Unable to find bitstring tag\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	if (asn1_find_tag(key_fp, ASN1_TAG_INTEGER) < 0) {
		fprintf(stderr,
			"Error: Unable to find integer tag (modulus)\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	bn modulus;
	modulus.size = asn1_get_length(key_fp);
	for (size_t i = 0; i < modulus.size; i++)
		modulus.data[i] = getc(key_fp);
	if (!modulus.data[0]) { /* Skip the leading 0 */
		modulus.size--;
		memmove(modulus.data, modulus.data + 1, modulus.size);
	}

	if (asn1_find_tag(key_fp, ASN1_TAG_INTEGER) < 0) {
		fprintf(stderr,
			"Error: Unable to find integer tag(publicExponent)\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	bn exponent;
	exponent.size = asn1_get_length(key_fp);
	for (size_t i = 0; i < exponent.size; i++)
		exponent.data[i] = getc(key_fp);

	bn result = RSA_trapdoor_big(message, exponent, modulus);

	for (size_t i = 0; i < result.size; i++) {
		printf("%02x ", result.data[i]);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}

	printf("\n");

	ret = EXIT_SUCCESS;

out:
	if (message_fp)
		fclose(message_fp);
	if (key_fp)
		fclose(key_fp);
	return ret;
}

#define ASN1_TAG_MASK 0xdf /* Take out P/C flag */
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
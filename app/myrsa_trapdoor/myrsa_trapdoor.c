/** myrsa_trapdoor.c - Perform RSA trapdoor function with PKCS #1 public key
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include "asn1.h"
#include "myrsa.h"
#include "memfp.h"

static int rsa_process_pubkey(const ASN1Object *rsa_pubkey,
			      ASN1Object *rsa_modulus,
			      ASN1Object *rsa_exponent);

int main(int argc, char *argv[])
{
	const char *message_file = NULL;
	const char *key_file = NULL;
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

	if (!message_file || !key_file) {
		fprintf(stderr, "Usage: %s -m <message file> -k <keyfile>\n",
			argv[0]);
		ret = EXIT_FAILURE;
		goto out;
	}

	message_fp = fopen(message_file, "rb");
	if (!message_fp) {
		perror("fopen message file");
		ret = EXIT_FAILURE;
		goto out;
	}
	key_fp = fopen(key_file, "rb");
	if (!key_fp) {
		perror("fopen key file");
		ret = EXIT_FAILURE;
		goto out;
	}
	static bn message;
	size_t message_size = fread(message.data, 1, MAX_DATA_SIZE, message_fp);
	if (message_size == 0) {
		fprintf(stderr, "Error reading message file\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	message.size = message_size;

	static uint8_t key_buf[MAX_DATA_SIZE];
	size_t key_size = fread(key_buf, 1, MAX_DATA_SIZE, key_fp);
	if (key_size == 0) {
		fprintf(stderr, "Error reading key file\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	struct memfp mp;
	memfp_open(&mp, key_buf, key_size);
	ASN1Object rsa_pubkey;
	if (asn1_load(&mp, &rsa_pubkey) != 0) {
		fprintf(stderr, "Error loading ASN.1 from key file\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	ASN1Object rsa_modulus, rsa_exponent;
	if (rsa_process_pubkey(&rsa_pubkey, &rsa_modulus, &rsa_exponent) != 0) {
		fprintf(stderr, "Error processing RSA public key\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	bn modulus, exponent;
	modulus.size = rsa_modulus.length;
	memcpy(modulus.data, rsa_modulus.value, modulus.size);
	exponent.size = rsa_exponent.length;
	memcpy(exponent.data, rsa_exponent.value, exponent.size);
	/* ASN.1 INTEGER has a leading 0 when the msb is set */
	trim_leading_zeros(&modulus);
	trim_leading_zeros(&exponent);

	bn result = RSA_trapdoor_big(message, exponent, modulus);
	for (size_t i = 0; i < result.size; i++) {
		printf("%02x ", result.data[i]);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}

	printf("\n");

out:
	if (message_fp)
		fclose(message_fp);
	if (key_fp)
		fclose(key_fp);
	return ret;
}

static int rsa_process_pubkey(const ASN1Object *rsa_pubkey,
			      ASN1Object *rsa_modulus, ASN1Object *rsa_exponent)
{
	/* 
	 * PKCS #1
	 * RSAPublicKey ::= SEQUENCE {
	 *     modulus           INTEGER,  -- n
	 *     publicExponent    INTEGER   -- e
	 * }
	 */
	if (asn1_get_tag(rsa_pubkey->tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Not a valid RSAPublicKey\n");
		return -1;
	}

	struct memfp mp;
	memfp_open(&mp, rsa_pubkey->value, rsa_pubkey->length);
	int c = mpeekc(&mp);
	if (asn1_get_tag(c) != ASN1_TAG_INTEGER) {
		fprintf(stderr, "Error: Not a valid RSA modulus\n");
		return -1;
	}
	if (asn1_load(&mp, rsa_modulus) != 0) {
		fprintf(stderr, "Error loading RSA modulus\n");
		return -1;
	}
	c = mpeekc(&mp);
	if (asn1_get_tag(c) != ASN1_TAG_INTEGER) {
		fprintf(stderr, "Error: Not a valid RSA exponent\n");
		return -1;
	}
	if (asn1_load(&mp, rsa_exponent) != 0) {
		fprintf(stderr, "Error loading RSA exponent\n");
		return -1;
	}

	memfp_close(&mp); /* Just clear the memory */

	return 0;
}

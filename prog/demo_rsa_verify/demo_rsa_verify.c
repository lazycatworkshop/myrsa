/**
 * myrsa_verify.c - Implementation of RSA functions.
 * 
 * This file contains the main function to verify a message with associated
 * RSA public key. The message is from a file, and the public key and modulus
 * are provided as arguments. The result is printed to stdout.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <getopt.h>
#include "myrsa.h"
#include "mycrc.h"

/* Define the long options */
static struct option long_options[] = {
	{ "key", required_argument, 0, 'k' },
	{ "modulus", required_argument, 0, 'm' },
	{ "message-file", required_argument, 0, 'f' },
	{ "signature", required_argument, 0, 's' },
	{ 0, 0, 0, 0 } // End of options marker
};

int main(int argc, char *argv[])
{
	int opt;
	int option_index = 0;
	uint64_t public_key = 0;
	uint64_t modulus = 0;
	char *message_file = NULL;
	uint64_t signature = 0;

	while ((opt = getopt_long(argc, argv, "k:m:f:s:", long_options,
				  &option_index)) != -1) {
		char *end_ptr = NULL;
		switch (opt) {
		case 'k':
			public_key = strtoull(optarg, &end_ptr, 10);
			break;
		case 'm':
			modulus = strtoull(optarg, &end_ptr, 10);
			break;
		case 'f':
			message_file = optarg;
			break;
		case 's':
			signature = strtoull(optarg, &end_ptr, 10);
			break;
		default: /* '?' */
			fprintf(stderr,
				"Usage: %s --key <public_key> --modulus <modulus> --message-file <message_file> --signature <signature>\n",
				argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (public_key == 0 || modulus == 0 || message_file == NULL ||
	    signature == 0) {
		fprintf(stderr,
			"Usage: %s --key <public_key> --modulus <modulus> --message-file <message_file> --signature <signature>\n",
			argv[0]);
		return EXIT_FAILURE;
	}

	if (signature > modulus) {
		fprintf(stderr, "Signature is larger than modulus\n");
		return EXIT_FAILURE;
	}

	/* Check the length of the file */
	FILE *fp = fopen(message_file, "r");
	if (fp == NULL) {
		perror("fopen");
		return EXIT_FAILURE;
	}

	fseek(fp, 0, SEEK_END);
	size_t file_length = ftell(fp);
	fclose(fp);

	/* Allocate message buffer based on the file length */
	char *message = malloc(file_length);
	if (message == NULL) {
		fprintf(stderr, "Failed to allocate memory for message\n");
		return EXIT_FAILURE;
	}

	/* Read the message from the file */
	fp = fopen(message_file, "r");
	if (fp == NULL) {
		perror("fopen");
		free(message);
		return EXIT_FAILURE;
	}

	size_t len = fread(message, 1, file_length, fp);
	fclose(fp);

	/* Calculate the CRC of the message */
#if 0
	uint16_t crc = crc16_ccitt(message, len);
#else
	uint32_t crc = crc32(message, len);
#endif

	/* Sign the message */
	uint32_t expected_crc = RSA_trapdoor(signature, public_key, modulus);
	printf("Expected CRC\t: %u\n", expected_crc);
	if (crc == expected_crc) {
		printf("Message verified\n");
	} else {
		printf("Actual CRC\t: %u\n", crc);
	}

	free(message);

	return EXIT_SUCCESS;
}

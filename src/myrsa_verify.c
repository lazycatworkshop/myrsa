/**
 * myrsa_verify.c - Implementation of RSA functions.
 * 
 * This file contains the main function to verify a message with associated
 * RSA public key. The message is from a file, and the public key and modulus
 * are provided as arguments. The result is printed to stdout.
 * Example:
 * 
 *         ./myrsa_verify public_key modulus message.txt 
 *
 * Author: Benjamin Chin.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <getopt.h>
#include "myrsa.h"

enum VERBOSE_LEVEL { QUIET = 0, VERBOSE = 1, DEBUG = 2 };

uint32_t verbose = QUIET;

/* Define the long options */
static struct option long_options[] = {
	{ "key", required_argument, 0, 'k' },
	{ "modulus", required_argument, 0, 'm' },
	{ "message-file", required_argument, 0, 'f' },
	{ "signature", required_argument, 0, 's' },
	{ "verbose", no_argument, 0, 'v' },
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

	while ((opt = getopt_long(argc, argv, "k:m:f:s:v", long_options,
				  &option_index)) != -1) {
		switch (opt) {
		case 'k':
			public_key = atoi(optarg);
			break;
		case 'm':
			modulus = atoi(optarg);
			break;
		case 'f':
			message_file = optarg;
			break;
		case 's':
			signature = atoi(optarg);
			break;
		case 'v':
			verbose++;
			break;
		default: /* '?' */
			fprintf(stderr,
				"Usage: %s --key <public_key> --modulus <modulus> --message-file <message_file> --signature <signature>[--verbose]\n",
				argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (public_key == 0 || modulus == 0 || message_file == NULL ||
	    signature == 0) {
		fprintf(stderr,
			"Usage: %s --key <public_key> --modulus <modulus> --message-file <message_file> --signature <signature> [--verbose]\n",
			argv[0]);
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

	/* Calculate the CRC32 of the message */
	uint16_t crc = crc16_ccitt(message, len);

	if (verbose > QUIET) {
		printf("CRC: 0x%08X\n", crc);
	}

	/* Sign the message */
	uint64_t expected_crc = RSA_trapdoor(signature, public_key, modulus);
	printf("Expected CRC: %lu\n", expected_crc);
	if (crc == expected_crc) {
		printf("Message verified\n");
	} else {
		printf("Actual CRC: %ul\n", crc);
	}

	free(message);

	return EXIT_SUCCESS;
}
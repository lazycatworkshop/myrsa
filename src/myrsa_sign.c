/**
 * myrsa_sign.c - Implementation of RSA functions.
 * 
 * This file contains the main function to sign a message using RSA. The
 * message is from a file, and the public key and modulus are provided as
 * arguments. The signature is printed to stdout.
 * Example:
 * 
 *         ./myrsa_sign public_key modulus message.txt 
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
	{ "private-key", required_argument, 0, 'k' },
	{ "modulus", required_argument, 0, 'm' },
	{ "message-file", required_argument, 0, 'f' },
	{ "verbose", no_argument, 0, 'v' },
	{ 0, 0, 0, 0 } // End of options marker
};

int main(int argc, char *argv[])
{
	int opt;
	int option_index = 0;
	uint64_t private_key = 0;
	uint64_t modulus = 0;
	char *message_file = NULL;

	while ((opt = getopt_long(argc, argv, "k:m:f:v", long_options,
				  &option_index)) != -1) {
		switch (opt) {
		case 'k':
			private_key = atoi(optarg);
			break;
		case 'm':
			modulus = atoi(optarg);
			break;
		case 'f':
			message_file = optarg;
			break;
		case 'v':
			verbose++;
			break;
		default: /* '?' */
			fprintf(stderr,
				"Usage: %s --key <private_key> --modulus <modulus> --message-file <message_file> [--verbose]\n",
				argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (private_key == 0 || modulus == 0 || message_file == NULL) {
		fprintf(stderr,
			"Usage: %s --private-key <private_key> --modulus <modulus> --message-file <message_file> [--verbose]\n",
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

	/* Calculate the CRC16 of the message */
	uint16_t crc = crc16_ccitt(message, len);

	if (crc > modulus) {
		fprintf(stderr, "CRC16 is larger than modulus\n");
		free(message);
		return EXIT_FAILURE;
	}

	if (verbose > QUIET) {
		printf("CRC: 0x%08X\n", crc);
	}

	/* Sign the message */
	uint64_t signature = RSA_trapdoor(crc, private_key, modulus);
	printf("Signature: %lu\n", signature);

	free(message);

	return EXIT_SUCCESS;
}

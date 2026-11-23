/** myrsa_sha256 - This program computes the SHA-256 hash value for a file
 *    and save the result to an output file. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include "mySHA.h"

static void print_usage()
{
	printf("Usage: myrsa_sha256 -i <input file> -o <output file>\n");
}

int main(int argc, char *argv[])
{
	const char *input_file = NULL;
	const char *output_file = NULL;
	int opt;
	FILE *fp = NULL;
	FILE *out_fp = NULL;
	uint8_t *buffer = NULL;

	while ((opt = getopt(argc, argv, "i:o:")) != -1) {
		switch (opt) {
		case 'i':
			input_file = optarg;
			break;
		case 'o':
			output_file = optarg;
			break;
		default:
			print_usage();
			return EXIT_FAILURE;
		}
	}

	if (input_file == NULL || output_file == NULL) {
		print_usage();
		return EXIT_FAILURE;
	}

	fp = fopen(input_file, "r");
	if (fp == NULL) {
		perror("Error: failed to open the input file\n");
		return EXIT_FAILURE;
	}

	/* File length */
	fseek(fp, 0, SEEK_END);
	size_t file_len = ftell(fp);
	rewind(fp);
	int ret = EXIT_SUCCESS;

	if (file_len == 0) {
		fprintf(stderr, "Error: input file is empty\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	buffer = malloc(file_len);
	if (buffer == NULL) {
		perror("Error: failed to allocate memory\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	size_t len = fread(buffer, 1, file_len, fp);
	if (len == 0) {
		perror("Error: failed to read the input file\n");
		ret = EXIT_FAILURE;
		free(buffer);
		goto out;
	}

	uint32_t H[SHA256_WORD_COUNT];
	SHA256_compute_hash(buffer, len, H);

	out_fp = fopen(output_file, "w");
	if (out_fp == NULL) {
		perror("Error: failed to open the output file\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	/* Write the hash value to the output file */
	uint8_t digest[SHA256_DIGEST_SIZE / 8]; /* In bytes */
	SHA256_get_digest(H, digest);
	fwrite(digest, 1, sizeof(digest), out_fp); /* In bytes */
out:
	if (buffer)
		free(buffer);
	if (fp)
		fclose(fp);
	if (out_fp)
		fclose(out_fp);

	return ret;
}

/** myrsa_sha1.c - This program calculate the SHA-1 value for an input file
 * and save the result to an output file. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include "mySHA.h"

#define MAX_FILE_SIZE (1024 << 2) /* 4K */

void print_usage()
{
	printf("Usage: myrsa_sha1 -i <input file> -o <output file>\n");
}

int main(int argc, char *argv[])
{
	char *input_file = NULL;
	char *output_file = NULL;
	int opt;
	FILE *fp = NULL;
	FILE *out_fp = NULL;

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
		perror("Error: failed to open the intput file\n");
		return EXIT_FAILURE;
	}

	out_fp = fopen(output_file, "w");
	if (out_fp == NULL) {
		perror("Error: failed to open the output file\n");
		fclose(fp);
		return EXIT_FAILURE;
	}

	char msg[MAX_FILE_SIZE];
	size_t len = fread(msg, 1, MAX_FILE_SIZE, fp);
	uint32_t H[SHA1_WORD_COUNT];
	SHA1_compute_hash(msg, len, H);

	uint8_t digest[SHA1_DIGEST_SIZE / 8];
	SHA1_get_digest(H, digest);
	fwrite(digest, 1, SHA1_DIGEST_SIZE / 8, out_fp);

	fclose(fp);
	fclose(out_fp);

	return EXIT_SUCCESS;
}
/** myrsa_sha256 - This program computes the SHA-256 hash value for a file
 *    and save the result to an output file. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include "mySHA.h"

int is_big_endian(void)
{
	union {
		uint32_t i;
		char c[4];
	} test_union = { 0x01020304 };

	return test_union.c[0] == 1;
}

#define ENDIAN_SWAP_32(x)                                                      \
	(((x) >> 24) | (((x) >> 8) & 0x0000FF00) | (((x) << 8) & 0x00FF0000) | \
	 ((x) << 24))

void print_usage()
{
	printf("Usage: myrsa_sha256 -i <input file> -o <output file>\n");
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

	/* File length */
	fseek(fp, 0, SEEK_END);
	size_t file_len = ftell(fp);
	rewind(fp);
	int ret = EXIT_SUCCESS;

	char *buffer = malloc(file_len);
	size_t len = fread(buffer, 1, file_len, fp);
	if (len == 0) {
		perror("Error: failed to read the input file\n");
		ret = EXIT_FAILURE;
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
	int big_endian = is_big_endian();
	for (int i = 0; i < SHA256_WORD_COUNT; i++) {
		if (!big_endian) {
			H[i] = ENDIAN_SWAP_32(H[i]);
		}
		fwrite(&H[i], sizeof(uint32_t), 1, out_fp);
	}

out:
	if (buffer)
		free(buffer);

	if (fp)
		fclose(fp);
	if (out_fp)
		fclose(out_fp);

	return ret;
}
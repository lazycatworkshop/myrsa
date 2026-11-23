/**
 * pem2der.c - Convert a PEM file to a DER file
 * This program reads a PEM file and converts it to a DER file.
 * The PEM file is assumed to contain a single base64 encoded block generated
 * by openssl.
 * The DER file will contain the decoded binary data.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include "pem_der.h"

int main(int argc, char *argv[])
{
	char *pemfile = NULL;
	char *derfile = NULL;
	FILE *ifp = NULL;
	FILE *ofp = NULL;
	char line[MAX_PEM_LINE_LENGTH];
	int c;
	int ret = EXIT_SUCCESS;

	while ((c = getopt(argc, argv, "p:d:")) != -1) {
		switch (c) {
		case 'p':
			pemfile = optarg;
			break;
		case 'd':
			derfile = optarg;
			break;
		default:
			fprintf(stderr, "Usage: %s -p pemfile -d derfile\n",
				argv[0]);
			ret = EXIT_FAILURE;
			goto out;
		}
	}

	if (!pemfile || !derfile) {
		fprintf(stderr, "Usage: %s -p pemfile -d derfile\n", argv[0]);
		ret = EXIT_FAILURE;
		goto out;
	}

	ifp = fopen(pemfile, "r");
	if (ifp == NULL) {
		perror("Error: Failed to open PEM file\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	// Check the length of the input file
	fseek(ifp, 0, SEEK_END);
	long file_length = ftell(ifp);
	fseek(ifp, 0, SEEK_SET); // Reset file pointer to the beginning

	if (file_length <= 0) {
		perror("Error: Input file is empty or could not determine the length.\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	/* Skip pre-EB */
	/* Boundary is '-' (one is sufficient) + ???... + LF by definition.
	 * Assume the pattern of openssl here.
	 */
	while (fgets(line, sizeof(line), ifp) != NULL) {
		if (strncmp(line, "-----BEGIN", 10) == 0) {
			break;
		}
	}
	if (feof(ifp)) {
		perror("Error: No PEM header found\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	/* Convert the base64 encoded data */
	ofp = fopen(derfile, "w");
	if (ofp == NULL) {
		perror("Error: Failed to open DER file\n");
		ret = 1;
		goto out;
	}

	/* ...with each line except the last containing exactly 64 printable
	 * characters and the final line containing 64 or less printable
	 * characters. 
	 */
	while (fgets(line, sizeof(line), ifp) != NULL) {
		if (strncmp(line, "-----END", 8) == 0) /* Until post-EB */
			break;
		uint8_t buf[MAX_DER_BUFFER_SIZE];
		size_t buf_len = sizeof(buf);
		if (pem2der(line, buf, &buf_len) != 0) {
			fprintf(stderr,
				"Error: Failed to convert PEM to DER\n");
			ret = EXIT_FAILURE;
			goto out;
		}
		fwrite(buf, 1, buf_len, ofp);
	}

	ret = EXIT_SUCCESS;

out:
	if (ifp) {
		fclose(ifp);
	}
	if (ofp) {
		fclose(ofp);
	}

	return ret;
}

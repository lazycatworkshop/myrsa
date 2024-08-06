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

#define MAX_LINE_LEN 1024
#define B64_LINE_LEN 64

static const uint8_t ascii2bin_table[128];

int main(int argc, char *argv[])
{
	char *pemfile = NULL;
	char *derfile = NULL;
	FILE *ifp = NULL;
	FILE *ofp = NULL;
	char line[MAX_LINE_LEN];
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

		/* 4 6-bit bytes -> 3 8-bit bytes */
		for (size_t i = 0; i < strlen(line) / 4; i++) {
			uint8_t a, b, c, d, out;

			a = ascii2bin_table[(size_t)line[i * 4]];
			b = ascii2bin_table[(size_t)line[i * 4 + 1]];
			c = ascii2bin_table[(size_t)line[i * 4 + 2]];
			d = ascii2bin_table[(size_t)line[i * 4 + 3]];

			out = (a << 2) | (b >> 4);
			fwrite(&out, sizeof(out), 1, ofp);
			if (line[i * 4 + 2] != '=') /* 1st padding character */
			{
				out = (b << 4) | (c >> 2);
				fwrite(&out, sizeof(out), 1, ofp);
			}
			if (line[i * 4 + 3] !=
			    '=') { /* 2nd padding character */
				out = (c << 6) | d;
				fwrite(&out, sizeof(out), 1, ofp);
			}
		}
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

#define NOT_B64 (64) /* Any random value > 63 */

/* The printable characters is a subset of ASCII */
static const uint8_t ascii2bin_table[128] = {
	/*  Base64 ASCII */
	NOT_B64, /* 0x00 */
	NOT_B64, /* 0x01 */
	NOT_B64, /* 0x02 */
	NOT_B64, /* 0x03 */
	NOT_B64, /* 0x04 */
	NOT_B64, /* 0x05 */
	NOT_B64, /* 0x06 */
	NOT_B64, /* 0x07 */
	NOT_B64, /* 0x08 */
	NOT_B64, /* 0x09 */
	NOT_B64, /* 0x0A */
	NOT_B64, /* 0x0B */
	NOT_B64, /* 0x0C */
	NOT_B64, /* 0x0D */
	NOT_B64, /* 0x0E */
	NOT_B64, /* 0x0F */
	NOT_B64, /* 0x10 */
	NOT_B64, /* 0x11 */
	NOT_B64, /* 0x12 */
	NOT_B64, /* 0x13 */
	NOT_B64, /* 0x14 */
	NOT_B64, /* 0x15 */
	NOT_B64, /* 0x16 */
	NOT_B64, /* 0x17 */
	NOT_B64, /* 0x18 */
	NOT_B64, /* 0x19 */
	NOT_B64, /* 0x1A */
	NOT_B64, /* 0x1B */
	NOT_B64, /* 0x1C */
	NOT_B64, /* 0x1D */
	NOT_B64, /* 0x1E */
	NOT_B64, /* 0x1F */
	NOT_B64, /* 0x20 */
	NOT_B64, /* 0x21 */
	NOT_B64, /* 0x22 */
	NOT_B64, /* 0x23 */
	NOT_B64, /* 0x24 */
	NOT_B64, /* 0x25 */
	NOT_B64, /* 0x26 */
	NOT_B64, /* 0x27 */
	NOT_B64, /* 0x28 */
	NOT_B64, /* 0x29 */
	NOT_B64, /* 0x2A */
	62, /* 0x2B - '+' */
	NOT_B64, /* 0x2C */
	NOT_B64, /* 0x2D */
	NOT_B64, /* 0x2E */
	63, /* 0x2F - '/' */
	52, /* 0x30 - '0' */
	53, /* 0x31 - '1' */
	54, /* 0x32 - '2' */
	55, /* 0x33 - '3' */
	56, /* 0x34 - '4' */
	57, /* 0x35 - '5' */
	58, /* 0x36 - '6' */
	59, /* 0x37 - '7' */
	60, /* 0x38 - '8' */
	61, /* 0x39 - '9' */
	NOT_B64, /* 0x3A */
	NOT_B64, /* 0x3B */
	NOT_B64, /* 0x3C */
	NOT_B64, /* 0x3D */
	NOT_B64, /* 0x3E */
	NOT_B64, /* 0x3F */
	NOT_B64, /* 0x40 */
	0, /* 0x41 - 'A' */
	1, /* 0x42 - 'B' */
	2, /* 0x43 - 'C' */
	3, /* 0x44 - 'D' */
	4, /* 0x45 - 'E' */
	5, /* 0x46 - 'F' */
	6, /* 0x47 - 'G' */
	7, /* 0x48 - 'H' */
	8, /* 0x49 - 'I' */
	9, /* 0x4A - 'J' */
	10, /* 0x4B - 'K' */
	11, /* 0x4C - 'L' */
	12, /* 0x4D - 'M' */
	13, /* 0x4E - 'N' */
	14, /* 0x4F - 'O' */
	15, /* 0x50 - 'P' */
	16, /* 0x51 - 'Q' */
	17, /* 0x52 - 'R' */
	18, /* 0x53 - 'S' */
	19, /* 0x54 - 'T' */
	20, /* 0x55 - 'U' */
	21, /* 0x56 - 'V' */
	22, /* 0x57 - 'W' */
	23, /* 0x58 - 'X' */
	24, /* 0x59 - 'Y' */
	25, /* 0x5A - 'Z' */
	NOT_B64, /* 0x5B */
	NOT_B64, /* 0x5C */
	NOT_B64, /* 0x5D */
	NOT_B64, /* 0x5E */
	NOT_B64, /* 0X5F */
	NOT_B64, /* 0x60 */
	26, /* 0x61 - 'a' */
	27, /* 0x62 - 'b' */
	28, /* 0x63 - 'c' */
	29, /* 0x64 - 'd' */
	30, /* 0x65 - 'e' */
	31, /* 0x66 - 'f' */
	32, /* 0x67 - 'g' */
	33, /* 0x68 - 'h' */
	34, /* 0x69 - 'i' */
	35, /* 0x6A - 'j' */
	36, /* 0x6B - 'k' */
	37, /* 0x6C - 'k' */
	38, /* 0x6D - 'm' */
	39, /* 0x6E - 'n' */
	40, /* 0x6F - 'o' */
	41, /* 0x70 - 'p' */
	42, /* 0x71 - 'q' */
	43, /* 0x72 - 'r' */
	44, /* 0x73 - 's' */
	45, /* 0x74 - 't' */
	46, /* 0x75 - 'u' */
	47, /* 0x76 - 'v' */
	48, /* 0x77 - 'w' */
	49, /* 0x78 - 'x' */
	50, /* 0x79 - 'y' */
	51, /* 0x7A - 'z' */
	NOT_B64, /* 0x7B */
	NOT_B64, /* 0x7C */
	NOT_B64, /* 0x7D */
	NOT_B64, /* 0x7E */
	NOT_B64 /* 0x7F */
};

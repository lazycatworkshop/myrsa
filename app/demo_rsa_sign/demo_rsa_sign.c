/* demo_rsa_sign.c - Demonstrate RSA signing with 64-bit integers.
 *
 * Usage: demo_rsa_sign -d <private exponent> -n <modulus> -f <document>
 *
 * The document is digested with CRC-32, then the digest is "encrypted" with
 * the private key: signature = digest^d mod n.
 *
 * CRC-32 is NOT a secure hash; it is used here only to keep the demo small.
 * RSA_trapdoor() multiplies two residues in 64 bits, so n must be < 2^32.
 * A 32-bit digest is reduced modulo n so that it is a valid RSA message.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <getopt.h>
#include "mycrc.h"
#include "myrsa.h"

#define MAX_DOC_SIZE 1024 /* 1 KB */

static void print_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s -d <private exponent> -n <modulus> -f <document>\n",
		prog);
}

static int parse_u64(const char *s, uint64_t *out)
{
	char *endptr;

	/* strtoull() accepts a leading '-', which we do not want */
	if (*s < '0' || *s > '9')
		return -1;
	errno = 0;
	*out = strtoull(s, &endptr, 10);
	if (errno != 0 || *endptr != '\0')
		return -1;
	return 0;
}

int main(int argc, char *argv[])
{
	uint64_t d = 0, n = 0;
	const char *path = NULL;
	int opt;

	while ((opt = getopt(argc, argv, "d:n:f:")) != -1) {
		switch (opt) {
		case 'd':
			if (parse_u64(optarg, &d) != 0) {
				fprintf(stderr,
					"Invalid private exponent: %s\n",
					optarg);
				return EXIT_FAILURE;
			}
			break;
		case 'n':
			if (parse_u64(optarg, &n) != 0) {
				fprintf(stderr, "Invalid modulus: %s\n",
					optarg);
				return EXIT_FAILURE;
			}
			break;
		case 'f':
			path = optarg;
			break;
		default:
			print_usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (d == 0 || n == 0 || path == NULL || optind != argc) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (n < 2 || n > UINT32_MAX) {
		fprintf(stderr, "Error: modulus must be in [2, 2^32 - 1].\n");
		return EXIT_FAILURE;
	}

	FILE *fp = fopen(path, "rb");
	if (fp == NULL) {
		perror("Error: cannot open the document");
		return EXIT_FAILURE;
	}

	uint8_t buf[MAX_DOC_SIZE];

	size_t len = fread(buf, 1, MAX_DOC_SIZE, fp);
	int too_big = (len == MAX_DOC_SIZE && fgetc(fp) != EOF);
	int read_err = ferror(fp);

	fclose(fp);
	if (read_err) {
		fprintf(stderr, "Error: failed to read the document\n");
		return EXIT_FAILURE;
	}
	if (too_big) {
		fprintf(stderr, "Error: document is too large (max %d bytes)\n",
			MAX_DOC_SIZE);
		return EXIT_FAILURE;
	}

	uint32_t crc = crc32(buf, len);

	uint64_t digest = crc % n;
	uint64_t sig = RSA_trapdoor(digest, d, n);

	printf("CRC-32: %" PRIu32 "\n", crc);
	printf("Digest: %" PRIu64 "\n", digest);
	printf("Signature: %" PRIu64 "\n", sig);

	return EXIT_SUCCESS;
}

/* demo_rsa_trapdoor.c - This is a program that demonstrates the RSA trapdoor
 * function. It takes a message and a public key as arguments, and prints the
 * result to stdout.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <getopt.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>

static uint64_t RSA_trapdoor(uint64_t message, uint64_t key, uint64_t modulus);

int main(int argc, char *argv[])
{
	int opt;
	uint64_t key = 0;
	uint64_t modulus = 0;
	uint64_t message = 0;
	char *endptr;

	while ((opt = getopt(argc, argv, "m:k:n:")) != -1) {
		switch (opt) {
		case 'k':
			errno = 0;
			key = strtoull(optarg, &endptr, 10);
			if (errno != 0 || *endptr != '\0') {
				fprintf(stderr, "Invalid key: %s\n", optarg);
				return EXIT_FAILURE;
			}
			break;
		case 'm':
			errno = 0;
			message = strtoull(optarg, &endptr, 10);
			if (errno != 0 || *endptr != '\0') {
				fprintf(stderr, "Invalid message: %s\n",
					optarg);
				return EXIT_FAILURE;
			}
			break;
		case 'n':
			errno = 0;
			modulus = strtoull(optarg, &endptr, 10);
			if (errno != 0 || *endptr != '\0') {
				fprintf(stderr, "Invalid modulus: %s\n",
					optarg);
				return EXIT_FAILURE;
			}
			break;
		default: /* '?' */
			fprintf(stderr,
				"Usage: %s -m <message> -k <key> -n <modulus>\n",
				argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (!key || !message || !modulus) {
		fprintf(stderr,
			"Usage: %s -m <message> -k <key> -n <modulus>\n"
			"Note: All arguments (-m, -k, -n) must be non-zero.\n",
			argv[0]);
		return EXIT_FAILURE;
	}

	if (message >= modulus) {
		fprintf(stderr,
			"Error: Message must be strictly less than the modulus.\n");
		return EXIT_FAILURE;
	}

	uint64_t r = RSA_trapdoor(message, key, modulus);
	printf("Result: %" PRIu64 "\n", r);

	return EXIT_SUCCESS;
}

/**
 * RSA_trapdoor - Encrypt or decrypt a message by RSA.
 *
 * @message: The message.
 * @key: The key.
 * @modulus: The modulus.
 * 
 * This function uses exponentiation by repeated squaring and multiplication
 * to compute C = M^key % modulus. The caller is responsible for ensuring
 * the input message is not greater than the modulus.
 * 
 * Return: The result of the modular exponentiation.
 */
static uint64_t RSA_trapdoor(uint64_t message, uint64_t key, uint64_t modulus)
{
	uint64_t r = 1;
	message = message %
		  modulus; /* Ensure initial message is within modulus range */

	while (key > 0) {
		if (key & 1) { /* Odd then multiply r by the current base */
			r = (r * message) % modulus;
		}
		message = (message * message) % modulus; /* Square */
		key >>= 1;
	}
	return r;
}

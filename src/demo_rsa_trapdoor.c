/** demo_rsa_trapdoor.c - This is a program that demonstrates the RSA trapdoor
 * function. It takes a message and a public key as arguments, and prints the
 * result to stdout.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <getopt.h>
#include <stdint.h>

uint64_t RSA_trapdoor(uint64_t message, uint64_t key, uint64_t modulus);

int main(int argc, char *argv[])
{
	int opt;
	uint64_t key = 0;
	uint64_t modulus = 0;
	uint64_t message = 0;

	while ((opt = getopt(argc, argv, "m:k:n:")) != -1) {
		switch (opt) {
		case 'k':
			key = atoi(optarg);
			break;
		case 'm':
			message = atoi(optarg);
			break;
		case 'n':
			modulus = atoi(optarg);
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
			"Usage: %s -m <message> -k <key> -n <modulus>\n",
			argv[0]);
		return EXIT_FAILURE;
	}

	uint64_t r = RSA_trapdoor(message, key, modulus);
	printf("Result: %lu\n", r);

	return EXIT_SUCCESS;
}

/**
 * RSA_trapdoor- Encrypt or decrypt a message by RSA.
 *
 * @message: The message.
 * @key: The key.
 * @modulus: The modulus.
 * 
 * This function uses exponentiation by "repeated squaring and multiplication
 * to compute C = M^key % modulus". The caller is responsible for ensuring
 * the input message is not greater than the modulus.
 * 
 * Return: The result of the modular exponentiation.
 */
uint64_t RSA_trapdoor(uint64_t message, uint64_t key, uint64_t modulus)
{
	uint64_t r = 1;
	while (key > 0) {
		if (key & 1) { /* Odd then multiply r by the current base */
			r = (r * message) % modulus;
		}
		message = (message * message) % modulus; /* Square */
		key >>= 1;
	}
	return r;
}
/* demo_rsa_keys.c - Implementation of RSA key generation functions. */

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include "myrsa_math.h"
#include "myrsa.h"

static int is_prime(uint64_t number)
{
	if (number <= 1)
		return 0;
	for (uint64_t i = 2; i * i <= number; i++) {
		if (number % i == 0)
			return 0;
	}
	return 1;
}

int main()
{
	uint64_t p;
	uint64_t q;
	uint64_t n;
	uint64_t e;
	uint64_t d;

	printf("Pick the first prime number: ");
	if (scanf("%" SCNu64, &p) != 1) {
		fprintf(stderr,
			"Error: invalid input for the first prime number.\n");
		return EXIT_FAILURE;
	}
	if (!is_prime(p)) {
		printf("Error: %" PRIu64 " is not a prime number.\n", p);
		return EXIT_FAILURE;
	}

	printf("Pick the second prime number: ");
	if (scanf("%" SCNu64, &q) != 1) {
		fprintf(stderr,
			"Error: invalid input for the second prime number.\n");
		return EXIT_FAILURE;
	}
	if (!is_prime(q)) {
		printf("Error: %" PRIu64 " is not a prime number.\n", q);
		return EXIT_FAILURE;
	}

	printf("p = %" PRIu64 ", q = %" PRIu64 "\n", p, q);

	generate_RSA_keys(p, q, &n, &e, &d);

	printf("Public Key: (%" PRIu64 ", %" PRIu64 ")\n", e, n);
	printf("Private Key: (%" PRIu64 ", %" PRIu64 ")\n", d, n);

	return EXIT_SUCCESS;
}

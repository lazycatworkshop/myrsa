/**
 * demo_rsa_keys.c - Implementation of RSA key generation functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "myrsa_math.h"
#include "myrsa.h"

bool is_prime(uint64_t number)
{
	if (number <= 1)
		return false;
	for (uint64_t i = 2; i * i <= number; i++) {
		if (number % i == 0)
			return false;
	}
	return true;
}

int main()
{
	uint64_t p;
	uint64_t q;
	uint64_t n;
	uint64_t e;
	uint64_t d;

	printf("Pick the first prime number: ");
	scanf("%lu", &p);
	if (!is_prime(p)) {
		printf("Error: %lu is not a prime number.\n", p);
		return EXIT_FAILURE;
	}

	printf("Pick the second prime number: ");
	scanf("%lu", &q);
	if (!is_prime(q)) {
		printf("Error: %lu is not a prime number.\n", q);
		return EXIT_FAILURE;
	}

	printf("p = %lu, q = %lu\n", p, q);

	generate_RSA_keys(p, q, &n, &e, &d);

	printf("Public Key: (%lu, %lu)\n", e, n);
	printf("Private Key: (%lu, %lu)\n", d, n);

	return EXIT_SUCCESS;
}

/**
 * demo_rsa_keys.c - Implementation of RSA key generation functions.
 *
 * Author: Benjamin Chin.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "myrsa_math.h"
#include "myrsa.h"

bool is_prime(uint32_t number)
{
	if (number <= 1)
		return false;
	for (uint32_t i = 2; i * i <= number; i++) {
		if (number % i == 0)
			return false;
	}
	return true;
}

int main()
{
	uint32_t p;
	uint32_t q;
	uint32_t n;
	uint32_t e;
	uint32_t d;

	printf("Pick the first prime number: ");
	scanf("%u", &p);
	if (!is_prime(p)) {
		printf("Error: %u is not a prime number.\n", p);
		return EXIT_FAILURE;
	}

	printf("Pick the second prime number: ");
	scanf("%u", &q);
	if (!is_prime(q)) {
		printf("Error: %u is not a prime number.\n", q);
		return EXIT_FAILURE;
	}

	printf("p = %u, q = %u\n", p, q);

	generate_RSA_keys(p, q, &n, &e, &d);

	printf("Public Key: (%u, %u)\n", e, n);
	printf("Private Key: (%u, %u)\n", d, n);

	return EXIT_SUCCESS;
}

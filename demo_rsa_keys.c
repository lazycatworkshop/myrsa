/**
 * demo_rsa_keys.c - Implementation of RSA key generation functions.
 *
 * Author: Benjamin Chin.
 */

#include <stdio.h>
#include <stdlib.h>
#include "myrsa_math.h"
#include "myrsa.h"

int main()
{
	uint32_t p;
	uint32_t q;
	uint32_t n;
	uint32_t e;
	uint32_t d;

	printf("Pick the first prime number: ");
	scanf("%u", &p);
	printf("Pick the second prime number: ");
	scanf("%u", &q);

	printf("p = %u, q = %u\n", p, q);

	generate_RSA_keys(p, q, &n, &e, &d);

	printf("Public Key: (%u, %u)\n", e, n);
	printf("Private Key: (%u, %u)\n", d, n);

	return EXIT_SUCCESS;
}

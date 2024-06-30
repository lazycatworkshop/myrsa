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
	unsigned int p;
	unsigned int q;
	unsigned int n;
	unsigned int e;
	unsigned int d;

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

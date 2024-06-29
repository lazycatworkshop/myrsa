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
	int p;
	int q;
	int e;
	int d;
	int n;

	printf("Pick the first prime number: ");
	scanf("%d", &p);
	printf("Pick the second prime number: ");
	scanf("%d", &q);

	printf("p = %d, q = %d\n", p, q);

	generate_RSA_keys(p, q, &e, &d, &n);

	printf("Public Key: (%d, %d)\n", e, n);
	printf("Private Key: (%d, %d)\n", d, n);

	return EXIT_SUCCESS;
}

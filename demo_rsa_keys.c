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
	int pub_key[2];
	int priv_key[2];

	printf("Pick the first prime number: ");
	scanf("%d", &p);
	printf("Pick the second prime number: ");
	scanf("%d", &q);

	printf("p = %d, q = %d\n", p, q);

	generate_RSA_keys(p, q, pub_key, priv_key);

	printf("Public Key: (%d, %d)\n", pub_key[0], pub_key[1]);
	printf("Private Key: (%d, %d)\n", priv_key[0], priv_key[1]);

	return EXIT_SUCCESS;
}

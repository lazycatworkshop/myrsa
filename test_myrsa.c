/**
 * test_myrsa.c - Unit tests for myrsa functions.
 *
 * Author: Benjamin Chin, ChatGPT.
 */

#include <assert.h>
#include <stdlib.h>
#include "myrsa.h"

int main()
{
	/* Test generate_RSA_keys function */
	{
		int pub_key[2];
		int priv_key[2];
		generate_RSA_keys(11, 17, pub_key, priv_key);
		assert(pub_key[0] > 0 && priv_key[0] > 0);
	}

	/* Add more tests as needed... */

	return EXIT_SUCCESS;
}
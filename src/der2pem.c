/** der2pem.c - A program to convert a DER file to a PEM one without the
 *  header and footer which needs to be appended according the type
 *  after the conversion. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdint.h>

void base64_encode_block(char *in, char *out, int len);

int main(int argc, char *argv[])
{
	char *der_file = NULL;
	char *pem_file = NULL;
	FILE *der_fp = NULL;
	FILE *pem_fp = NULL;
	char *der_buf = NULL;
	int ret = EXIT_SUCCESS;
	int c;

	while ((c = getopt(argc, argv, "d:p:")) != -1) {
		switch (c) {
		case 'd':
			der_file = optarg;
			break;
		case 'p':
			pem_file = optarg;
			break;
		default:
			fprintf(stderr,
				"Usage: %s -d <der_file> -p <pem_file>\n",
				argv[0]);
			ret = EXIT_FAILURE;
			goto out;
		}
	}

	if (der_file == NULL || pem_file == NULL) {
		fprintf(stderr, "Usage: %s -d <der_file> -p <pem_file>\n",
			argv[0]);
		ret = EXIT_FAILURE;
		goto out;
	}

	/* Open the input DER file */
	der_fp = fopen(der_file, "r");
	if (der_fp == NULL) {
		perror("Error: failed to open the input DER file\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	/* Open the output PEM file */
	pem_fp = fopen(pem_file, "w");
	if (pem_fp == NULL) {
		perror("Error: failed to open the output PEM file\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	/* Read the input */
	fseek(der_fp, 0, SEEK_END);
	size_t der_size = ftell(der_fp);
	fseek(der_fp, 0, SEEK_SET);
	der_buf = malloc(der_size);
	fread(der_buf, 1, der_size, der_fp);

	/* Convert to the output buffer */
	char *pem_buf = malloc(der_size * 2);
	size_t pem_size = 0;
	size_t l = der_size;
	size_t i = 0;
	while (l) {
		char b64[4];
		int len = l > 3 ? 3 : l;
		base64_encode_block(der_buf + i, b64, len);
		for (int j = 0; j < 4; j++) {
			pem_buf[pem_size++] = b64[j];
		}
		l -= len;
		i += len;
		if (i % 48 == 0)
			pem_buf[pem_size++] = '\n';
	}
	pem_buf[pem_size++] = '\n';

	/* Write the output */
	fwrite(pem_buf, 1, pem_size, pem_fp);

out:
	if (der_fp != NULL)
		fclose(der_fp);
	if (pem_fp != NULL)
		fclose(pem_fp);

	if (der_buf != NULL)
		free(der_buf);

	return ret;
}

char *base64_table =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
char base64_encode(char c)
{
	return base64_table[(int)c];
}

void base64_encode_block(char *in, char *out, int len)
{
	out[0] = base64_encode(in[0] >> 2);
	out[1] = base64_encode(((in[0] & 0x03) << 4) | (in[1] >> 4));
	out[2] = base64_encode(((in[1] & 0x0f) << 2) | (in[2] >> 6));
	out[3] = base64_encode(in[2] & 0x3f);

	if (len == 1) {
		out[2] = '=';
		out[3] = '=';
	} else if (len == 2) {
		out[3] = '=';
	}
}

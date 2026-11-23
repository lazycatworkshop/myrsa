/* p7b_extract_cert.c - Extract certificates from a PKCS#7 (P7B) file and save 
 * them individually 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <stdint.h>
#include "oid.h"
#include "cms.h"

 int main(int argc, char *argv[])
{
	int ret = EXIT_SUCCESS;
	int opt;
	char *cms_file = NULL;
	char *cert_file = NULL;
	FILE *cms_fp = NULL;
	FILE *cert_fp = NULL;
	while ((opt = getopt(argc, argv, "i:o:")) != -1) {
		switch (opt) {
		case 'i':
			cms_file = optarg;
			break;
		case 'o':
			cert_file = optarg;
			break;
		default:
			fprintf(stderr,
				"Usage: %s -i <cms file> -o <cert file>\n",
				argv[0]);
			ret = EXIT_FAILURE;
			goto out;
		}
	}

	if (cms_file == NULL || cert_file == NULL) {
		fprintf(stderr, "Usage: %s -i <cms file> -o <cert file>\n",
			argv[0]);
		ret = EXIT_FAILURE;
		goto out;
	}

	cms_fp = fopen(cms_file, "r");
	if (cms_fp == NULL) {
		fprintf(stderr, "Error: Cannot open file %s: %s\n", cms_file,
			strerror(errno));
		ret = EXIT_FAILURE;
		goto out;
	}

	cert_fp = fopen(cert_file, "w");
	if (cert_fp == NULL) {
		fprintf(stderr, "Error: Cannot open file %s: %s\n", cert_file,
			strerror(errno));
		ret = EXIT_FAILURE;
		goto out;
	}

	struct CMS_contentInfo cms;
	memset(&cms, 0, sizeof(cms));

	size_t read_len = fread(cms.buf, 1, CMS_MAX_SIZE, cms_fp);
	if (read_len == 0) {
		fprintf(stderr, "Error: File is empty\n");
		ret = EXIT_SUCCESS; /* NO I/O failure */
		goto out;
	}
	cms.len = read_len;

	if (process_cms(&cms) != 0) {
		fprintf(stderr, "Error: Failed to process .p7b file\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	int oid_type = asn1_get_oid_type(&cms.contentType);
	struct CMS_SignedData sd;
	switch (oid_type) {
	case OID_TYPES_id_signedData:
		if (process_cms_SignedData(cms.content.value,
					   cms.content.length, &sd) != 0) {
			fprintf(stderr,
				"Error: Failed to process SignedData\n");
			ret = EXIT_FAILURE;
			goto out;
		}
		break;
	default:
		fprintf(stderr, "Error: Unsupported content type: %d\n",
			oid_type);
		ret = EXIT_FAILURE;
		goto out;
	}

	if (fwrite(sd.certificates.value, 1, sd.certificates.length, cert_fp) != sd.certificates.length) {
		fprintf(stderr, "Error: Failed to write certificates to file\n");
		ret = EXIT_FAILURE;
		goto out;
	}
out:
	if (cms_fp)
		fclose(cms_fp);
	if (cert_fp)
		fclose(cert_fp);
	return ret;
}

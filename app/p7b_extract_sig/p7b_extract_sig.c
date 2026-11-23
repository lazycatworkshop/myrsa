/* p7b_extract_sig.c - Extract the signature value of the first SignerInfo from
 * a PKCS#7 (P7B) file and save it to a file
 * 
 * NOTE: Assume only one SignerInfo in the SignerInfos SET.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <stdint.h>
#include "oid.h"
#include "cms.h"

static void print_usage(const char *prog_name)
{
	fprintf(stderr, "Usage: %s -i <cms file> -o <signature file>\n",
		prog_name);
}

static int get_first_signature(const ASN1Object *signerInfos,
			       struct CMS_SignerInfo *si_data);

int main(int argc, char *argv[])
{
	int ret = EXIT_SUCCESS;
	int opt;
	char *cms_file = NULL;
	char *sig_file = NULL;
	FILE *cms_fp = NULL;
	FILE *sig_fp = NULL;

	while ((opt = getopt(argc, argv, "i:o:")) != -1) {
		switch (opt) {
		case 'i':
			cms_file = optarg;
			break;
		case 'o':
			sig_file = optarg;
			break;
		default:
			print_usage(argv[0]);
			ret = EXIT_FAILURE;
			goto out;
		}
	}

	if (cms_file == NULL || sig_file == NULL) {
		print_usage(argv[0]);
		ret = EXIT_FAILURE;
		goto out;
	}

	cms_fp = fopen(cms_file, "rb");
	if (cms_fp == NULL) {
		fprintf(stderr, "Error: Cannot open file %s: %s\n", cms_file,
			strerror(errno));
		ret = EXIT_FAILURE;
		goto out;
	}

	static struct CMS_contentInfo cms;
	memset(&cms, 0, sizeof(cms));

	size_t read_len = fread(cms.buf, 1, CMS_MAX_SIZE, cms_fp);
	if (read_len == 0) {
		fprintf(stderr, "Error: File is empty\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	cms.len = read_len;

	if (process_cms(&cms) != 0) {
		fprintf(stderr, "Error: Failed to process .p7b file\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	int oid_type = asn1_get_oid_type(&cms.contentType);
	if (oid_type != OID_TYPES_id_signedData) {
		fprintf(stderr, "Error: Unsupported content type: %d\n",
			oid_type);
		ret = EXIT_FAILURE;
		goto out;
	}

	struct CMS_SignedData sd;
	memset(&sd, 0, sizeof(sd));
	if (process_cms_SignedData(cms.content.value, cms.content.length,
				   &sd) != 0) {
		fprintf(stderr, "Error: Failed to process SignedData\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	struct CMS_SignerInfo si_data;
	memset(&si_data, 0, sizeof(si_data));
	if (get_first_signature(&sd.signerInfos, &si_data) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	sig_fp = fopen(sig_file, "wb");
	if (sig_fp == NULL) {
		fprintf(stderr, "Error: Cannot open file %s: %s\n", sig_file,
			strerror(errno));
		ret = EXIT_FAILURE;
		goto out;
	}

	if (fwrite(si_data.signature.value, 1, si_data.signature.length,
		   sig_fp) != si_data.signature.length) {
		fprintf(stderr, "Error: Failed to write signature to file\n");
		ret = EXIT_FAILURE;
		goto out;
	}
out:
	if (cms_fp)
		fclose(cms_fp);
	if (sig_fp)
		fclose(sig_fp);
	return ret;
}

static int get_first_signature(const ASN1Object *signerInfos,
			       struct CMS_SignerInfo *si_data)
{
	if (asn1_get_tag(signerInfos->tag) != ASN1_TAG_SET ||
	    signerInfos->length == 0) {
		fprintf(stderr, "Error: No SignerInfo found\n");
		return -1;
	}

	struct memfp mp;
	memfp_open(&mp, signerInfos->value, signerInfos->length);

	ASN1Object si;
	if (asn1_load_tag(&mp, &si, ASN1_TAG_SEQUENCE) != 0) {
		fprintf(stderr, "Error: Expected SEQUENCE for SignerInfo\n");
		goto fail;
	}
	memfp_close(&mp);

	memfp_open(&mp, si.value, si.length);
	if (asn1_load_tag(&mp, &si_data->version, ASN1_TAG_INTEGER) != 0) {
		fprintf(stderr, "Error: Expected INTEGER for version\n");
		goto fail;
	}
	if (asn1_load(&mp, &si_data->sid) != 0) {
		fprintf(stderr, "Error: Expected SignerIdentifier\n");
		goto fail;
	}
	if (asn1_load(&mp, &si_data->digestAlgorithm) != 0) {
		fprintf(stderr, "Error: Expected DigestAlgorithmIdentifier\n");
		goto fail;
	}
	if (asn1_get_tag(mpeekc(&mp)) == ASN1_TAG_CONTEXT_SPECIFIC_0 &&
	    asn1_load_tag(&mp, &si_data->signedAttrs,
			  ASN1_TAG_CONTEXT_SPECIFIC_0) != 0) {
		fprintf(stderr, "Error: Expected SignedAttributes\n");
		goto fail;
	}
	if (asn1_load(&mp, &si_data->signatureAlgorithm) != 0) {
		fprintf(stderr,
			"Error: Expected SignatureAlgorithmIdentifier\n");
		goto fail;
	}
	if (asn1_load_tag(&mp, &si_data->signature, ASN1_TAG_OCTET_STRING) !=
	    0) {
		fprintf(stderr, "Error: Expected SignatureValue\n");
		goto fail;
	}

	memfp_close(&mp);
	return 0;
fail:
	memfp_close(&mp);
	return -1;
}

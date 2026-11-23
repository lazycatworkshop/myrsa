/* p7b_extract_signed_attrs.c - Extract the signedAttrs of the first SignerInfo
 * from a PKCS#7 (P7B) file and save it to a file
 *
 * The signedAttrs is stored as [0] IMPLICIT in the SignerInfo, but the
 * signature is computed over its DER encoding as a SET OF (RFC 5652, 5.4).
 * Therefore the output has the tag replaced by SET (0x31), ready to be hashed.
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

#define DER_SET_TAG 0x31

static void print_usage(const char *prog_name)
{
	fprintf(stderr, "Usage: %s -i <cms file> -o <signedAttrs file>\n",
		prog_name);
}

static int get_first_signed_attrs(const ASN1Object *signerInfos,
				  struct CMS_SignerInfo *si_data);

static int write_signed_attrs(const struct CMS_SignerInfo *si_data,
			      FILE *out_fp);

int main(int argc, char *argv[])
{
	int ret = EXIT_SUCCESS;
	int opt;
	char *cms_file = NULL;
	char *out_file = NULL;
	FILE *cms_fp = NULL;
	FILE *out_fp = NULL;

	while ((opt = getopt(argc, argv, "i:o:")) != -1) {
		switch (opt) {
		case 'i':
			cms_file = optarg;
			break;
		case 'o':
			out_file = optarg;
			break;
		default:
			print_usage(argv[0]);
			ret = EXIT_FAILURE;
			goto out;
		}
	}

	if (cms_file == NULL || out_file == NULL) {
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
	if (get_first_signed_attrs(&sd.signerInfos, &si_data) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (si_data.signedAttrs.value == NULL) {
		fprintf(stderr, "Error: No signedAttrs in SignerInfo\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	out_fp = fopen(out_file, "wb");
	if (out_fp == NULL) {
		fprintf(stderr, "Error: Cannot open file %s: %s\n", out_file,
			strerror(errno));
		ret = EXIT_FAILURE;
		goto out;
	}

	if (write_signed_attrs(&si_data, out_fp) == 0) {
		fprintf(stderr, "Error: failed to write signedAttrs to file\n");
		ret = EXIT_FAILURE;
		goto out;
	}
out:
	if (cms_fp)
		fclose(cms_fp);
	if (out_fp)
		fclose(out_fp);
	return ret;
}

static int get_first_signed_attrs(const ASN1Object *signerInfos,
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

	memfp_close(&mp);
	return 0;
fail:
	memfp_close(&mp);
	return -1;
}

/* Encode a DER length; return the number of octets written. */
static size_t der_encode_length(size_t len, uint8_t out[])
{
	size_t n = 0;
	size_t tmp;

	if (len < 0x80) {
		out[0] = (uint8_t)len;
		return 1;
	}
	for (tmp = len; tmp; tmp >>= 8)
		n++;
	out[0] = (uint8_t)(ASN1_LONG_FORM_MASK | n);
	for (size_t i = 0; i < n; i++)
		out[n - i] = (uint8_t)(len >> (8 * i));
	return n + 1;
}

static int write_signed_attrs(const struct CMS_SignerInfo *si_data,
			      FILE *out_fp)
{
	int ret = 0; /* Actual written bytes */

	/* SignedAttributes ::= SET SIZE (1..MAX) OF Attribute */
	/* Replace [0] with SET tag since here it is a stand along structure */
	fputc(ASN1_TAG_SET | ASN1_C_P_MASK, out_fp);
	++ret;

	/* Write length */
	uint8_t len_buf[5];
	size_t len = der_encode_length(si_data->signedAttrs.length, len_buf);
	ret += len;
	if (fwrite(len_buf, 1, len, out_fp) != len) {
		fprintf(stderr, "Error: Failed to write length to file\n");
		return -1;
	}

	/* Write value */
	if (fwrite(si_data->signedAttrs.value, 1, si_data->signedAttrs.length,
		   out_fp) != si_data->signedAttrs.length) {
		fprintf(stderr, "Error: Failed to write signedAttrs to file\n");
		return -1;
	}

	return ret;
}

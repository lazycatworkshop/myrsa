/* cms.c - Implementation file for CMS (Cryptographic Message Syntax) handling */

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include "asn1.h"
#include "oid.h"
#include "memfp.h"
#include "cms.h"

int process_cms(struct CMS_contentInfo *cms)
{
	int ret = 0;
	struct memfp mp;
	memfp_open(&mp, cms->buf, cms->len);

	/* Top level */
	int c = mgetc(&mp);
	if (asn1_get_tag(c) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Expected top level SEQUENCE\n");
		ret = -1;
		goto out;
	}
	size_t top_len = asn1_get_length(&mp); /* Advance to the contents */

	if (asn1_load_tag(&mp, &cms->contentType, ASN1_TAG_OBJECT_IDENTIFIER)) {
		fprintf(stderr, "Error: Failed to load contentType\n");
		ret = -1;
		goto out;
	}

	if (asn1_load_tag(&mp, &cms->content, ASN1_TAG_CONTEXT_SPECIFIC_0)) {
		fprintf(stderr, "Error: Failed to load content\n");
		ret = -1;
		goto out;
	}

	/* Top level is not read by asn1_load_tag, it would not reach the last
	   EOC */
	if (top_len == ASN1_INDEFINITE_LENGTH) {
		if (mgetc(&mp) != 0 || /* EOC tag */
		    mgetc(&mp) != 0) { /* EOC length */
			fprintf(stderr, "Error: Missing top level EOC\n");
			ret = -1;
			goto out;
		}
	}

	if ((size_t)mtell(&mp) != cms->len) {
		fprintf(stderr,
			"Error: process_cms - Read count %zu, expected %zu\n",
			(size_t)mtell(&mp), cms->len);
		ret = -1;
		goto out;
	}

out:
	memfp_close(&mp); /* It does not matter. Just to match memfp_open */
	return ret;
}

int process_cms_SignedData(const uint8_t buf[], size_t buf_len,
			   struct CMS_SignedData *signed_data)
{
	int ret = 0;
	struct memfp mp;
	memfp_open(&mp, buf, buf_len);

	/* Top level SEQUENCE */
	if (asn1_get_tag(mgetc(&mp)) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Expected top level SEQUENCE\n");
		ret = -1;
		goto out;
	}
	asn1_get_length(&mp); /* Advance to the contents */

	if (asn1_load(&mp, &signed_data->version)) {
		fprintf(stderr, "Error: Failed to load version\n");
		ret = -1;
		goto out;
	}

	if (asn1_load(&mp, &signed_data->digestAlgorithms)) {
		fprintf(stderr, "Error: Failed to load digestAlgorithms\n");
		ret = -1;
		goto out;
	}

	if (asn1_load(&mp, &signed_data->encapContentInfo)) {
		fprintf(stderr, "Error: Failed to load encapContentInfo\n");
		ret = -1;
		goto out;
	}

	if (asn1_get_tag(mpeekc(&mp)) == ASN1_TAG_CONTEXT_SPECIFIC_0) {
		asn1_load_tag(&mp, &signed_data->certificates,
			      ASN1_TAG_CONTEXT_SPECIFIC_0);
	}
	if (asn1_get_tag(mpeekc(&mp)) == ASN1_TAG_CONTEXT_SPECIFIC_1) {
		asn1_load_tag(&mp, &signed_data->crls,
			      ASN1_TAG_CONTEXT_SPECIFIC_1);
	}

	if (asn1_load(&mp, &signed_data->signerInfos)) {
		fprintf(stderr, "Error: Failed to load signerInfos\n");
		ret = -1;
		goto out;
	}

out:
	memfp_close(&mp);

	return ret;
}

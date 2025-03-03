/** p7b_extract_sig - A program to retrieve the singerInfos' signature 
 * from a PKCS #7 file.
 * 
 * Usage: p7b_extract_sig -i <cms file> -o <sig file>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

typedef struct asn1 {
	int c; /* top level tag (8 bits) */
	int length;
	uint8_t *value;
} ASN1;

/* PKCS#7 SignedData structure */
typedef struct {
	ASN1 version;
	ASN1 digestAlgorithms;
	ASN1 encapContentInfo;
	ASN1 certificates;
	ASN1 crls;
	ASN1 signerInfos;
} signed_data_content;

typedef struct {
	uint8_t buf[1024 << 3]; /* 8 KB buffer */
	signed_data_content content;
} signed_data;

#define MAX_SINGER_INFO_NO 3

typedef struct {
	ASN1 version;
	ASN1 sid;
	ASN1 digestAlgorithm;
	ASN1 signedAttr;
	ASN1 signatureAlgorithm;
	ASN1 signature;
	ASN1 unsignedAttr;
} signer_info_t;

void p7b_init(signed_data *pkcs7)
{
	memset(pkcs7, 0, sizeof(*pkcs7));
};

int process_pkcs7_buf(signed_data *pkcs7, uint8_t *buf, size_t len);
int process_signer_infos(ASN1 *singer_infos, signer_info_t *singer_info,
			 int *max_singer_info_no);
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
			fprintf(stderr,
				"Usage: %s -i <cms file> -o <sig file>\n",
				argv[0]);
			ret = EXIT_FAILURE;
			goto out;
		}
	}

	if (cms_file == NULL || sig_file == NULL) {
		fprintf(stderr, "Usage: %s -i <cms file> -o <sig file>\n",
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

	sig_fp = fopen(sig_file, "w");
	if (sig_fp == NULL) {
		fprintf(stderr, "Error: Cannot open file %s: %s\n", sig_file,
			strerror(errno));
		ret = EXIT_FAILURE;
		goto out;
	}

	signed_data pkcs7;
	p7b_init(&pkcs7);

	fseek(cms_fp, 0, SEEK_END);
	size_t cms_size = ftell(cms_fp);
	if (cms_size > sizeof(pkcs7.buf)) {
		fprintf(stderr, "Error: file too large\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	fseek(cms_fp, 0, SEEK_SET);
	fread(pkcs7.buf, 1, cms_size, cms_fp);

	int error = process_pkcs7_buf(&pkcs7, pkcs7.buf, cms_size);
	if (error < 0) {
		fprintf(stderr, "Error: failed to process PKCS#7 file\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	signer_info_t signer_info;
	int no = 0;
	error = process_signer_infos(&pkcs7.content.signerInfos, &signer_info,
				     &no);
	if (error < 0) {
		fprintf(stderr, "Error: failed to process singerInfos\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	error = fwrite(signer_info.signature.value, 1,
		       signer_info.signature.length, sig_fp);
	if (error < 0) {
		fprintf(stderr, "Error: failed to write signature: %s\n",
			strerror(errno));
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

struct memfp {
	uint8_t *buf;
	uint8_t *pos;
	uint8_t *end;
};

void memfp_open(struct memfp *mp, uint8_t *buf, size_t len)
{
	mp->buf = buf;
	mp->pos = buf;
	mp->end = buf + len;
}

int mgetc(struct memfp *mp)
{
	int c = *mp->pos;
	(mp->pos)++;
	return c;
}

void mungetc(struct memfp *mp)
{
	(mp->pos)--;
}

long mtell(struct memfp *mp)
{
	return mp->pos - mp->buf;
}

void mseek(struct memfp *mp, long offset, int whence)
{
	switch (whence) {
	case SEEK_SET:
		mp->pos = mp->buf + offset;
		break;
	case SEEK_CUR:
		mp->pos += offset;
		break;
	case SEEK_END:
		mp->pos = mp->end + offset;
		break;
	}
}

void memfp_close(struct memfp *mp)
{
	mp->buf = NULL;
	mp->pos = NULL;
	mp->end = NULL;
}

#define ASN1_TAG_MASK 0xdf /* Take out P/C flag */
#define ASN1_C_P_MASK 0x20
#define ASN1_TAG_CONSTRUCTIVE 0x20
#define ASN1_IS_CONSTRUCTED(identifier) ((identifier) & ASN1_C_P_MASK)

enum ASN1_TAG {
	ASN1_TAG_EOC = 0x00,
	ASN1_TAG_BOOLEAN = 0x01,
	ASN1_TAG_INTEGER = 0x02,
	ASN1_TAG_BIT_STRING = 0x03,
	ASN1_TAG_OCTET_STRING = 0x04,
	ASN1_TAG_NULL = 0x05,
	ASN1_TAG_OBJECT_IDENTIFIER = 0x06,
	ASN1_TAG_UTF8_STRING = 0x0c,
	ASN1_TAG_RELATIVE_OID = 0x0d,
	ASN1_TAG_SEQUENCE = 0x10,
	ASN1_TAG_SET = 0x11,
	ASN1_TAG_PRINTABLE_STRING = 0x13,
	ASN1_TAG_VID_STRING = 0x15,
	ASN1_TAG_IA5_STRING = 0x16,
	ASN1_TAG_UTC = 0x17,
	ASN1_TAG_GENERALIZED_TIME = 0x18,
	ASN1_TAG_CONTEXT_SPECIFIC_0 = 0x80,
	ASN1_TAG_CONTEXT_SPECIFIC_1 = 0x81,
	ASN1_TAG_CONTEXT_SPECIFIC_2 = 0x82,
	ASN1_TAG_CONTEXT_SPECIFIC_3 = 0x83,
	ASN1_TAG_CONTEXT_SPECIFIC_4 = 0x84,
	ASN1_TAG_CONTEXT_SPECIFIC_5 = 0x85,
	ASN1_TAG_CONTEXT_SPECIFIC_6 = 0x86,
	ASN1_TAG_CONTEXT_SPECIFIC_7 = 0x87,
	ASN1_TAG_CONTEXT_SPECIFIC_8 = 0x88,
	/* Add more tags here */
	ASN1_TAG_UNKNOWN = 0xff
};

#define ASN1_INDEFINITE_FORM 0x80
#define ASN1_INDEFINITE_LENGTH 0xffff

int asn1_get_length(struct memfp *mp)
{
	/* Length octets */
	int length_bytes = 0;
	int length = mgetc(mp);
	if (length != ASN1_INDEFINITE_FORM) {
		if (length & 0x80) {
			length_bytes = length & 0x7f;
			length = 0;
			for (int i = 0; i < length_bytes; i++) {
				length = (length << 8) | mgetc(mp);
			}
		}
	} else {
		length = ASN1_INDEFINITE_LENGTH;
	}

	return length;
}

enum SIGNED_DATA_STATE {
	SIGNED_DATA_START,
	SIGNED_DATA_VERSION,
	SIGNED_DATA_DIGEST_ALGORITHMS,
	SIGNED_DATA_ENCAP_CONTENT_INFO,
	SIGNED_DATA_CERTIFICATES,
	SIGNED_DATA_CRLS,
	SIGNED_DATA_SIGNER_INFOS,
	SIGNED_DATA_DONE
};

int asn1_walk_thru(struct memfp *mp, int length);

int load_component(struct memfp *mp, ASN1 *asn1_ptr)
{
	asn1_ptr->c = mgetc(mp);
	asn1_ptr->length = asn1_get_length(mp);
	asn1_ptr->value = mp->pos;
	if (asn1_ptr->length == ASN1_INDEFINITE_LENGTH)
		asn1_ptr->length = asn1_walk_thru(mp, asn1_ptr->length);
	else
		mseek(mp, asn1_ptr->length, SEEK_CUR);

	return 1;
}

int process_pkcs7_buf(signed_data *pkcs7, uint8_t *buf, size_t len)
{
	int ret = 0; /* Default failure case */
	struct memfp mem;
	struct memfp *mp = &mem;
	memfp_open(mp, buf, len);

	/* Top level */
	int c = mgetc(mp);
	int tag_number = c & ASN1_TAG_MASK;
	if (tag_number != ASN1_TAG_SEQUENCE) {
		ret = -1;
		goto out;
	}

	asn1_get_length(mp);

	c = mgetc(mp);
	tag_number = c & ASN1_TAG_MASK;
	if (tag_number != ASN1_TAG_OBJECT_IDENTIFIER) {
		ret = -1;
		goto out;
	}

	int length = asn1_get_length(mp);
	mseek(mp, length, SEEK_CUR);

	/* content */
	c = mgetc(mp);
	tag_number = c & ASN1_TAG_MASK;
	if (tag_number != ASN1_TAG_CONTEXT_SPECIFIC_0) {
		ret = -1;
		goto out;
	}

	length = asn1_get_length(mp);

	enum SIGNED_DATA_STATE state = SIGNED_DATA_START;

	int offset1, offset2;
	while (length > 0) {
		offset1 = mtell(mp);

		switch (state) {
		case SIGNED_DATA_START:
			c = mgetc(&mem);
			tag_number = c & ASN1_TAG_MASK;
			if (tag_number != ASN1_TAG_SEQUENCE) {
				ret = -1;
				goto out;
			}
			asn1_get_length(&mem);
			state = SIGNED_DATA_VERSION;
			break;
		case SIGNED_DATA_VERSION:
			if (load_component(mp, &pkcs7->content.version) <= 0) {
				ret = -1;
				goto out;
			}
			state = SIGNED_DATA_DIGEST_ALGORITHMS;
			break;
		case SIGNED_DATA_DIGEST_ALGORITHMS:
			if (load_component(mp,
					   &pkcs7->content.digestAlgorithms) <=
			    0) {
				ret = -1;
				goto out;
			}
			state = SIGNED_DATA_ENCAP_CONTENT_INFO;
			break;
		case SIGNED_DATA_ENCAP_CONTENT_INFO:
			if (load_component(mp,
					   &pkcs7->content.encapContentInfo) <=
			    0) {
				ret = -1;
				goto out;
			}
			state = SIGNED_DATA_CERTIFICATES;
			break;
		case SIGNED_DATA_CERTIFICATES:
			int back_pos = mtell(mp);
			c = mgetc(mp);
			tag_number = c & ASN1_TAG_MASK;
			if (tag_number != ASN1_TAG_CONTEXT_SPECIFIC_0) {
				mungetc(mp);
				state = SIGNED_DATA_CRLS;
				break;
			}

			/* It is an IMPLICIT option, SET tag is skipped.
			 * Rewind to start at [0].
			  */
			mseek(mp, back_pos, SEEK_SET);

			if (load_component(mp, &pkcs7->content.certificates) <=
			    0) {
				ret = -1;
				goto out;
			}
			state = SIGNED_DATA_CRLS;
			break;
		case SIGNED_DATA_CRLS:
			c = mgetc(mp);
			tag_number = c & ASN1_TAG_MASK;
			if (tag_number != ASN1_TAG_CONTEXT_SPECIFIC_1) {
				mungetc(mp);
				state = SIGNED_DATA_SIGNER_INFOS;
				break;
			}
			if (load_component(mp, &pkcs7->content.crls) <= 0) {
				ret = -1;
				goto out;
			}
			state = SIGNED_DATA_SIGNER_INFOS;
			break;

		case SIGNED_DATA_SIGNER_INFOS:
			if (load_component(mp, &pkcs7->content.signerInfos) <=
			    0) {
				ret = -1;
				goto out;
			}
			state = SIGNED_DATA_DONE;
			break;
		case SIGNED_DATA_DONE:
			if (length > 0)
				length = 0;
			ret = 1;
			break;

		default:
			ret = -1;
			break;
		}

		offset2 = mtell(mp);
		length -= offset2 - offset1;
	}

	ret = 1;

out:
	memfp_close(mp);

	return ret;
}

/* asn1_walk_thru - Find the actual lengh of an ASN.1 syntax 
 * @pos: Pointer to the buffer
 * @length: Length of the buffer
 * 
 * This function will walk through the ASN.1 syntax and return the actual
 * length of the ASN.1 syntax.
 * 
 * Return: The actual length of the ASN.1 syntax
 */
int asn1_walk_thru(struct memfp *mp, int length)
{
	int ret = 0;

	while (length > 0) {
		int len = 0;
		int offset1, offset2 = 0;
		offset1 = mtell(mp);

		/* Tag */
		int c = mgetc(mp);
		int tag = c & ASN1_TAG_MASK;

		/* Length */
		len = asn1_get_length(mp);

		if (tag == ASN1_TAG_EOC) {
			length = 0; /* Complete current level */
			/*ret += 2; */ /* Do not include EOC in the value component */
			continue; /* Back to the upper level */
		}

		/* Content */
		if (len == ASN1_INDEFINITE_LENGTH)
			len = asn1_walk_thru(mp, len);
		else
			mseek(mp, len, SEEK_CUR);

		offset2 = mtell(mp);
		int len1 = offset2 - offset1;
		length -= len1;
		ret += len1;
	}

	return ret;
}

typedef struct {
	ASN1 algorithm;
	ASN1 SignatureValue;
} Signature;

int process_signer_infos(ASN1 *signer_infos, signer_info_t *signer_info,
			 int *signer_info_no)
{
	int ret = 0;
	struct memfp mp;
	memfp_open(&mp, signer_infos->value, signer_infos->length);

	int offset1, offset2;
	*signer_info_no = 0;
	int length = signer_infos->length;
	while (length > 0) {
		offset1 = mtell(&mp);

		mgetc(&mp); /* SEQUENCE */
		asn1_get_length(&mp);

		ret = load_component(&mp, &signer_info->version);
		if (ret <= 0)
			goto out;

		ret = load_component(&mp, &signer_info->sid);
		if (ret <= 0)
			goto out;

		ret = load_component(&mp, &signer_info->digestAlgorithm);
		if (ret <= 0)
			goto out;

		/* signerAttr is optional */
		int c = mgetc(&mp);
		int tag = c & ASN1_TAG_MASK;
		if (tag == ASN1_TAG_CONTEXT_SPECIFIC_0) {
			mungetc(&mp);
			ret = load_component(&mp, &signer_info->signedAttr);
			if (ret <= 0)
				goto out;
		} else {
			mungetc(&mp);
		}

		ret = load_component(&mp, &signer_info->signatureAlgorithm);
		if (ret <= 0)
			goto out;

		ret = load_component(&mp, &signer_info->signature);
		if (ret <= 0)
			goto out;

		/* unsignedAttr is optional */
		c = mgetc(&mp);
		tag = c & ASN1_TAG_MASK;
		if (tag == ASN1_TAG_CONTEXT_SPECIFIC_1) {
			mungetc(&mp);
			ret = load_component(&mp, &signer_info->unsignedAttr);
			if (ret <= 0)
				goto out;
		} else {
			mungetc(&mp);
		}

		(*signer_info_no)++;

		offset2 = mtell(&mp);
		length -= offset2 - offset1;
	}
out:
	memfp_close(&mp);
	return ret;
}

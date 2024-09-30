/** x509_extract_pubkey.c -   Retrieve the public key component from a public
 *  key certificate. The output contains the public key in the DER format complying PKCS #1.
 * 
 * This is similar to x509_extract_sig.c except that it extracts the public key.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

typedef struct asn1 {
	uint8_t tag;
	uint8_t *value;
	size_t length;
} ASN1;

typedef struct {
	ASN1 version;
	ASN1 serial_number;
	ASN1 signature;
	ASN1 issuer;
	ASN1 validity;
	ASN1 subject;
	ASN1 subject_public_key_info;
	ASN1 issuer_unique_id; /* Not supported yet */
	ASN1 subject_unique_id; /* Not supported yet */
	ASN1 extensions;
} TBSCertificate;

typedef struct {
	ASN1 algorithm;
	ASN1 SignatureValue;
} Signature;

typedef struct {
	uint8_t buf[1024 << 2]; /* 4 KB buffer */
	TBSCertificate tbs;
	Signature sig;
} X509;

void x509_init(X509 *x509)
{
	memset(x509, 0, sizeof(*x509));
}

int process_x509_buf(X509 *x509);
uint8_t get_version(ASN1 *version);
size_t get_public_key_info(X509 *x509, uint8_t pub_key[], size_t len);

#define ASN1_TAG_MASK 0xdf /* Take out P/C flag */

int main(int argc, char *argv[])
{
	char *cert_file = NULL;
	char *pub_key_file = NULL;
	FILE *cert_fp = NULL;
	FILE *pub_key_fp = NULL;
	int ret = EXIT_SUCCESS;
	int c;
	while ((c = getopt(argc, argv, "c:p:")) != -1) {
		switch (c) {
		case 'c':
			cert_file = optarg;
			break;
		case 'p':
			pub_key_file = optarg;
			break;
		default:
			fprintf(stderr,
				"Usage: %s -c <cert_file> -p <pub_key_file>\n",
				argv[0]);
			ret = EXIT_FAILURE;
			goto out;
		}
	}

	if (cert_file == NULL || pub_key_file == NULL) {
		fprintf(stderr, "Usage: %s -c <cert_file> -p <pub_key_file>\n",
			argv[0]);
		ret = EXIT_FAILURE;
		goto out;
	}

	/* Open the input certificate file */
	cert_fp = fopen(cert_file, "r");
	if (cert_fp == NULL) {
		perror("Error: failed to open the input certificate file\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	/* Open the output public key file */
	pub_key_fp = fopen(pub_key_file, "w");
	if (pub_key_fp == NULL) {
		perror("Error: failed to open the output public key file\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	X509 x509;
	x509_init(&x509);
	fseek(cert_fp, 0, SEEK_END);
	size_t cert_size = ftell(cert_fp);
	if (cert_size > sizeof(x509.buf)) {
		fprintf(stderr, "Error: certificate file too large\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	fseek(cert_fp, 0, SEEK_SET);
	fread(x509.buf, 1, cert_size, cert_fp);

	/* Process the certificate */
	if (process_x509_buf(&x509) != 0) {
		fprintf(stderr, "Error: failed to process the certificate\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	/* Write the public key to the output file */
	uint8_t pub_key[1024];
	size_t pub_key_len =
		get_public_key_info(&x509, pub_key, sizeof(x509.buf));
	if (fwrite(pub_key, 1, pub_key_len, pub_key_fp) != pub_key_len) {
		perror("Error: failed to write the public key to the output file\n");
		ret = EXIT_FAILURE;
		goto out;
	}

out:
	if (cert_fp)
		fclose(cert_fp);
	if (pub_key_fp)
		fclose(pub_key_fp);
	return ret;
}

size_t asn1_get_length(uint8_t *pos, size_t *length_bytes)
{
	size_t length = *pos++; /* length octet */
	*length_bytes = 0;
	if (length & 0x80) {
		*length_bytes = length & 0x7f;
		length = 0;
		for (int i = 0; i < *length_bytes; i++) {
			length = (length << 8) | *pos++;
		}
	}
	(*length_bytes)++;

	return length;
}

uint8_t *load_version(ASN1 *version, uint8_t *pos);
uint8_t *load_serial_number(ASN1 *serial_number, uint8_t *pos);
uint8_t *load_signature(ASN1 *signature, uint8_t *pos);
uint8_t *load_issuer(ASN1 *issuer, uint8_t *pos);
uint8_t *load_validity(ASN1 *validity, uint8_t *pos);
uint8_t *load_subject(ASN1 *subject, uint8_t *pos);
uint8_t *load_subject_public_key_info(ASN1 *subject_public_key_info,
				      uint8_t *pos);
uint8_t *load_extensions(ASN1 *extensions, uint8_t *pos);
uint8_t *load_signature_algorithm(ASN1 *signature_algorithm, uint8_t *pos);
uint8_t *load_signature_value(ASN1 *signature_value, uint8_t *pos);

int process_x509_buf(X509 *x509)
{
	int ret = EXIT_SUCCESS;

	uint8_t *p = x509->buf;
	/* Top most SEQUENCE */
	uint8_t c = *p++;
	if (c != 0x30) {
		fprintf(stderr, "Error: Not a valid DER encoded certificate\n");
		ret = EXIT_FAILURE;
		goto process_x509_buf_out;
	}

	size_t length_bytes;
	asn1_get_length(p, &length_bytes);
	p += length_bytes;

	/* 2nd SEQUENCE for TBSCertificate */
	c = *p++;
	asn1_get_length(p, &length_bytes);
	p += length_bytes;

	/* Default case : no Context-specific 0 */
	int is_v1 = (*p & 0xa0) ? 0 : 1;
	uint8_t version = 1; /* Default v1 */
	if (!is_v1) {
		p = load_version(&x509->tbs.version, p);
		version = get_version(&x509->tbs.version) + 1;
	}

	p = load_serial_number(&x509->tbs.serial_number, p);

	p = load_signature(&x509->sig.algorithm, p);

	p = load_issuer(&x509->tbs.issuer, p);

	p = load_validity(&x509->tbs.validity, p);

	p = load_subject(&x509->tbs.subject, p);

	p = load_subject_public_key_info(&x509->tbs.subject_public_key_info, p);

	if (version != 1)
		p = load_extensions(&x509->tbs.extensions, p);

	p = load_signature_algorithm(&x509->sig.algorithm, p);

	p = load_signature_value(&x509->sig.SignatureValue, p);

process_x509_buf_out:
	return ret;
}

/** 
 * Load an ASN.1 object from the buffer.
 * @param asn1 ASN.1 object to load
 * @param pos Pointer to the buffer
 * @param label Label for debugging
 * 
 * @return Pointer to the next byte after the loaded ASN.1 object
 * 
 */
uint8_t *load_asn1(ASN1 *asn1, uint8_t *pos, const char *label)
{
	asn1->tag = *pos++;
	size_t length_bytes;
	asn1->length = asn1_get_length(pos, &length_bytes);
	pos += length_bytes;
	asn1->value = pos;
#ifdef DEBUG
	printf("%s: ", label);
	if (asn1->length > 16)
		printf("\n");
	for (int i = 0; i < asn1->length; i++) {
		printf("%02x ", asn1->value[i]);
		if (i % 16 == 15)
			printf("\n");
	}
	printf("\n");
#endif
	return pos + asn1->length;
}

uint8_t get_version(ASN1 *version)
{
	return version->value[2];
}

uint8_t *load_version(ASN1 *version, uint8_t *pos)
{
	return load_asn1(version, pos, "Version");
}

uint8_t *load_serial_number(ASN1 *serial_number, uint8_t *pos)
{
	return load_asn1(serial_number, pos, "Serial number");
}

uint8_t *load_signature(ASN1 *signature, uint8_t *pos)
{
	return load_asn1(signature, pos, "Signature");
}

uint8_t *load_issuer(ASN1 *issuer, uint8_t *pos)
{
	return load_asn1(issuer, pos, "Issuer");
}

uint8_t *load_validity(ASN1 *validity, uint8_t *pos)
{
	return load_asn1(validity, pos, "Validity");
}

uint8_t *load_subject(ASN1 *subject, uint8_t *pos)
{
	return load_asn1(subject, pos, "Subject");
}

uint8_t *load_subject_public_key_info(ASN1 *subject_public_key_info,
				      uint8_t *pos)
{
	return load_asn1(subject_public_key_info, pos,
			 "Subject Public Key Info");
}

uint8_t *load_extensions(ASN1 *extensions, uint8_t *pos)
{
	return load_asn1(extensions, pos, "Extensions");
}

uint8_t *load_signature_algorithm(ASN1 *signature_algorithm, uint8_t *pos)
{
	return load_asn1(signature_algorithm, pos, "Signature Algorithm");
}

uint8_t *load_signature_value(ASN1 *signature_value, uint8_t *pos)
{
	return load_asn1(signature_value, pos, "Signature Value");
}

size_t get_public_key_info(X509 *x509, uint8_t pub_key[], size_t len)
{
	if (len < x509->tbs.subject_public_key_info.length)
		return 0;
	/* Upper level SEQUENCE for openssl rsa compatibility */
	pub_key[0] = 0x30;
	pub_key[1] = 0x82;
	pub_key[2] = x509->tbs.subject_public_key_info.length >> 8;
	pub_key[3] = x509->tbs.subject_public_key_info.length & 0xff;

	memcpy(&pub_key[4], x509->tbs.subject_public_key_info.value,
	       x509->tbs.subject_public_key_info.length);

	return x509->tbs.subject_public_key_info.length + 4;
}

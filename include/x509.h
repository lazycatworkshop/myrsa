/* x509.h - Header file for X.509 certificate handling */
#ifndef X509_H
#define X509_H

#include <stdint.h>
#include "asn1.h"

#define X509_CERTIFICATE_MAX_SIZE 4096
#pragma pack(push, 1)
typedef struct {
	uint8_t asn1_buf[X509_CERTIFICATE_MAX_SIZE];
	size_t cert_len;
	/* Top level */
	ASN1Object TBSCertificate;
	ASN1Object signatureAlgorithm;
	ASN1Object signatureValue;

	/* TBSCertificate components */
	ASN1Object version;
	ASN1Object serial_number;
	ASN1Object signature;
	ASN1Object issuer;
	ASN1Object validity;
	ASN1Object subject;
	ASN1Object subject_public_key_info;
	ASN1Object issuer_unique_id; /* Not supported yet */
	ASN1Object subject_unique_id; /* Not supported yet */
	ASN1Object extensions;

	/* Underline components*/
	ASN1Object subjectPublicKeyAlgorithm;
	ASN1Object subjectPublicKey;
	ASN1Object rsaPublicKeyModulus;
	ASN1Object rsaPublicKeyExponent;
} X509Certificate;
#pragma pack(pop)

enum X509_VERSION { X509_VERSION_V1 = 0, X509_VERSION_V2, X509_VERSION_V3 };

int process_x509_certificate(X509Certificate *cert);
int X509_process_TBSCertificate(X509Certificate *cert);
int X509_get_version(const X509Certificate *cert, enum X509_VERSION *version);
void X509_print_version(enum X509_VERSION version);
void X509_print_serial_number(const ASN1Object *serial_number);
int X509_get_algorithm_oid(const ASN1Object *signature_algorithm, uint32_t *oid,
			   int *oid_length);
void X509_print_name(const ASN1Object *name);
void X509_dump8(const uint8_t *buf, size_t len);
void X509_print_AlgorithmIdentifier(const ASN1Object *alg_id);
void X509_print_signature(const ASN1Object *signature);
void X509_print_public_key(const ASN1Object *public_key);
void X509_print_attribute_type_and_value(const ASN1Object *att_value_obj);

#endif /* X509_H */

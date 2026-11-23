/* cms.h - Header file for CMS (Cryptographic Message Syntax) handling */

#ifndef CMS_H
#define CMS_H

#include <stdint.h>
#include "asn1.h"

#define CMS_MAX_SIZE (1024 << 3) /* 8 KB */

/*
ContentInfo ::= SEQUENCE {
	contentType ContentType,
	content [0] EXPLICIT ANY DEFINED BY contentType }
 */
struct CMS_contentInfo {
	uint8_t buf[CMS_MAX_SIZE];
	size_t len;

	ASN1Object contentType;
	ASN1Object content;
};

/*
SignedData ::= SEQUENCE {
	version CMSVersion,
	digestAlgorithms DigestAlgorithmIdentifiers,
	encapContentInfo EncapsulatedContentInfo,
	certificates [0] IMPLICIT CertificateSet OPTIONAL,
	crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
	signerInfos SignerInfos }
*/
struct CMS_SignedData {
	ASN1Object version;
	ASN1Object digestAlgorithms;
	ASN1Object encapContentInfo;
	ASN1Object certificates;
	ASN1Object crls;
	ASN1Object signerInfos;
};

/*
SignerInfo ::= SEQUENCE {
	version 			CMSVersion,
	sid 				SignerIdentifier,
	digestAlgorithm 		DigestAlgorithmIdentifier,
	signedAttrs 		[0] 	IMPLICIT SignedAttributes OPTIONAL,
	signatureAlgorithm		SignatureAlgorithmIdentifier,
	signature 			SignatureValue,
	unsignedAttrs 	[1] 	IMPLICIT UnsignedAttributes OPTIONAL }
*/
struct CMS_SignerInfo {
	ASN1Object version;
	ASN1Object sid;
	ASN1Object digestAlgorithm;
	ASN1Object signedAttrs;
	ASN1Object signatureAlgorithm;
	ASN1Object signature;
	ASN1Object unsignedAttrs;
};

int process_cms(struct CMS_contentInfo *cms);
int process_cms_SignedData(const uint8_t buf[], size_t buf_len,
			   struct CMS_SignedData *signed_data);

#endif /* CMS_H */

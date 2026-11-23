/* p7b_text.c - A program to display the content of .p7b file, DER encoded, in
 * text.
 * 
 *	Usage : p7b_text -f <filename>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include "asn1.h"
#include "oid.h"
#include "cms.h"
#include "x509.h"

static void print_CMS_SignedData(const struct CMS_SignedData *sd);

int main(int argc, char *argv[])
{
	FILE *fp = NULL;
	int c;
	int ret = EXIT_SUCCESS;

	while ((c = getopt(argc, argv, "f:")) != -1) {
		switch (c) {
		case 'f':
			fp = fopen(optarg, "rb");
			if (fp == NULL) {
				fprintf(stderr,
					"Error: Failed to open file '%s' - %s\n",
					optarg, strerror(errno));
				ret = EXIT_FAILURE;
				goto out;
			}
			break;
		default:
			fprintf(stderr, "Usage: %s -f <file>\n", argv[0]);
			ret = EXIT_FAILURE;
			goto out;
		}
	}

	if (fp == NULL) {
		fprintf(stderr, "Usage: %s -f <file>\n", argv[0]);
		ret = EXIT_FAILURE;
		goto out;
	}

	c = getc(fp);
	if (c == '-') { /* Encapsulate Boundary in PEM */
		fprintf(stderr, "Error: File is in PEM format\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	fseek(fp, 0, SEEK_SET);

	struct CMS_contentInfo cms;
	memset(&cms, 0, sizeof(cms));

	size_t read_len = fread(cms.buf, 1, CMS_MAX_SIZE, fp);
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

	printf("contentType: ");
	int oid_type = asn1_get_oid_type(&cms.contentType);
	asn1_print_oid(&cms.contentType);
	printf("\n");

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
		print_CMS_SignedData(&sd);
		break;
	default:
		fprintf(stderr, "Error: Unsupported content type: %d\n",
			oid_type);
		ret = EXIT_FAILURE;
		goto out;
	}

out:
	if (fp)
		fclose(fp);

	return ret;
}

static void print_digestAlgorithms(const ASN1Object *digestAlgorithms)
{
	/*
		DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
		DigestAlgorithmIdentifier ::= AlgorithmIdentifier

		RFC 8410

		AlgorithmIdentifier  ::=  SEQUENCE  {
       		algorithm   OBJECT IDENTIFIER,
       		parameters  ANY DEFINED BY algorithm OPTIONAL
   		}
	*/
	if (asn1_get_tag(digestAlgorithms->tag) != ASN1_TAG_SET) {
		fprintf(stderr,
			"Error: Expected SET for DigestAlgorithmIdentifiers\n");
		return;
	}

	size_t len = digestAlgorithms->length;
	struct memfp mp;
	memfp_open(&mp, digestAlgorithms->value, len);
	ASN1Object obj;
	while (len) {
		long start_pos = mtell(&mp);

		if (asn1_load(&mp, &obj) == 0) {
			X509_print_AlgorithmIdentifier(&obj);
		} else {
			fprintf(stderr,
				"Error: Expected AlgorithmIdentifier\n");
			return;
		}

		len -= mtell(&mp) - start_pos;
		if (len)
			printf(", ");
	}
}

static void print_encapContentInfo(const ASN1Object *eci)
{
	/*
		EncapsulatedContentInfo ::= SEQUENCE {
		eContentType ContentType,
		eContent [0] EXPLICIT OCTET STRING OPTIONAL }
	*/

	if (asn1_get_tag(eci->tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr,
			"Error: Expected SEQUENCE for EncapsulatedContentInfo\n");
		exit(EXIT_FAILURE);
	}
	size_t len = eci->length;

	struct memfp mp;
	memfp_open(&mp, eci->value, eci->length);
	long start_offset = mtell(&mp);

	printf("  eContentType: ");
	ASN1Object obj;
	if (asn1_load_tag(&mp, &obj, ASN1_TAG_OBJECT_IDENTIFIER) == 0) {
		asn1_print_oid(&obj);
		printf("\n");
	} else {
		fprintf(stderr,
			"Error: Expected OBJECT IDENTIFIER for eContentType\n");
		exit(EXIT_FAILURE);
	}

	if (!(len - (mtell(&mp) - start_offset))) {
		/* eContent is OPTIONAL */
		return;
	}

	if (asn1_get_tag(mpeekc(&mp)) == (ASN1_TAG_CONTEXT_SPECIFIC_0)) {
		mgetc(&mp); /* Consume the [0] tag */
		asn1_get_length(&mp);

		if (asn1_load_tag(&mp, &obj, ASN1_TAG_OCTET_STRING) == 0) {
			printf("  eContent:\n");
			asn1_print_octet_string(&obj);
		}
	}

	memfp_close(&mp); /* Just match the open */
}

static void print_issuerAndSerialNumber(const ASN1Object *issuerAndSerialNumber)
{
	/*
	IssuerAndSerialNumber ::= SEQUENCE {
		issuer Name,
		serialNumber CertificateSerialNumber }

	CertificateSerialNumber ::= INTEGER
	*/

	if (asn1_get_tag(issuerAndSerialNumber->tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr,
			"Error: Expected SEQUENCE for IssuerAndSerialNumber\n");
		exit(EXIT_FAILURE);
	}

	struct memfp mp;
	memfp_open(&mp, issuerAndSerialNumber->value,
		   issuerAndSerialNumber->length);
	mseek(&mp, 0, SEEK_SET);

	printf("    issuer: ");
	ASN1Object obj;
	if (asn1_load(&mp, &obj) == 0) {
		X509_print_name(&obj);
	} else {
		fprintf(stderr, "Error: Expected SEQUENCE for issuer\n");
		exit(EXIT_FAILURE);
	}

	printf("\n");

	if (asn1_load_tag(&mp, &obj, ASN1_TAG_INTEGER) == 0) {
		printf("    serialNumber: ");
		X509_print_serial_number(&obj);
	} else {
		fprintf(stderr, "Error: Expected INTEGER for serialNumber\n");
		exit(EXIT_FAILURE);
	}

	memfp_close(&mp);
}

static void print_sid(const ASN1Object *sid)
{
	/*
		SignerIdentifier ::= CHOICE {
		issuerAndSerialNumber IssuerAndSerialNumber,
		subjectKeyIdentifier [0] SubjectKeyIdentifier }	


		CertificateSerialNumber ::= INTEGER
		
		SubjectKeyIdentifier ::= OCTET STRING

	*/
	struct memfp mp;
	memfp_open(&mp, sid->value, sid->length);
	mseek(&mp, 0, SEEK_SET);
	ASN1Object obj;
	switch (asn1_get_tag(sid->tag)) {
	case ASN1_TAG_SEQUENCE:
		printf("issuerAndSerialNumber:\n");
		print_issuerAndSerialNumber(sid);
		break;
	case ASN1_TAG_CONTEXT_SPECIFIC_0:
		printf("subjectKeyIdentifier: ");
		if (asn1_is_implicit(sid->tag)) { /* Expected IMPLICIT */
			X509_dump8(sid->value, sid->length);
		} else {
			if (asn1_load_tag(&mp, &obj, ASN1_TAG_OCTET_STRING) ==
			    0) {
				asn1_print_octet_string(&obj);
			} else {
				fprintf(stderr,
					"Error: Expected OCTET STRING for subjectKeyIdentifier\n");
				exit(EXIT_FAILURE);
			}
		}
		break;
	default:
		fprintf(stderr, "Error: Unknown SignerIdentifier choice\n");
		exit(EXIT_FAILURE);
	}

	memfp_close(&mp);
}

static void print_CMSAlgorithmProtection(const ASN1Object *obj)
{
	/* 
	CMSAlgorithmProtection ::= SEQUENCE {
    		digestAlgorithm     DigestAlgorithmIdentifier,
    		signatureAlgorithm  [1] SignatureAlgorithmIdentifier OPTIONAL,
    		macAlgorithm        [2] MessageAuthenticationCodeAlgorithm OPTIONAL
		}
		(WITH COMPONENTS { signatureAlgorithm PRESENT, macAlgorithm ABSENT } |
 		WITH COMPONENTS { signatureAlgorithm ABSENT, macAlgorithm PRESENT })
	
	NOTE: RFC 6211 default to IMPLICIT
	
		*/
	if (asn1_get_tag(obj->tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr,
			"Error: Expected SEQUENCE for CMSAlgorithmProtection\n");
		exit(EXIT_FAILURE);
	}

	struct memfp mp;
	memfp_open(&mp, obj->value, obj->length);
	mseek(&mp, 0, SEEK_SET);

	ASN1Object alg_obj;
	if (asn1_load(&mp, &alg_obj) == 0) {
		printf("      digestAlgorithm: ");
		X509_print_AlgorithmIdentifier(&alg_obj);
	} else {
		fprintf(stderr,
			"Error: Expected AlgorithmIdentifier for digestAlgorithm\n");
		exit(EXIT_FAILURE);
	}

	printf("\n");

	int tag = asn1_get_tag(mgetc(&mp));
	if (!asn1_is_implicit(tag)) {
		fprintf(stderr,
			"Error: Expected implicit tag for signatureAlgorithm or macAlgorithm\n");
		exit(EXIT_FAILURE);
	}

	asn1_get_length(&mp); /* Advance to content */

	if (tag == ASN1_TAG_CONTEXT_SPECIFIC_1) {
		/* SignatureAlgorithmIdentifier ::= AlgorithmIdentifier */
		if (asn1_load(&mp, &alg_obj) == 0) {
			printf("      signatureAlgorithm: ");
			asn1_print_oid(&alg_obj);
		} else {
			fprintf(stderr,
				"Error: Failed to load signatureAlgorithm\n");
			exit(EXIT_FAILURE);
		}
	} else if (tag == ASN1_TAG_CONTEXT_SPECIFIC_2) {
		/* MessageAuthenticationCodeAlgorithm ::= AlgorithmIdentifier */
		if (asn1_load(&mp, &alg_obj) == 0) {
			printf("      macAlgorithm: ");
			asn1_print_oid(&alg_obj);
		} else {
			fprintf(stderr, "Error: Failed to load macAlgorithm\n");
			exit(EXIT_FAILURE);
		}
	} else {
		fprintf(stderr,
			"Error: Expected signatureAlgorithm or macAlgorithm\n");
		exit(EXIT_FAILURE);
	}
	asn1_load_tag(&mp, &alg_obj, ASN1_TAG_NULL); /* Consume unused NULL */

	memfp_close(&mp);
}

static void print_ContentHints(const ASN1Object *contentHints)
{
	/* 
	ExtendedSecurityServices
	{ iso(1) member-body(2) us(840) rsadsi(113549)
	pkcs(1) pkcs-9(9) smime(16) modules(0) ess(2) }
	DEFINITIONS IMPLICIT TAGS ::=

	contentHints |id-aa-contentHint [ESS] 

	ContentHints ::= SEQUENCE {
		contentDescription UTF8String (SIZE (1..MAX)) OPTIONAL,
		contentType ContentType }
	*/
	int tag = contentHints->tag;
	if (asn1_get_tag(tag) == ASN1_TAG_UTF8_STRING) {
		/* Workaround some exceptions */
		printf("      contentDescription: ");
		asn1_print_printable_string(contentHints);
		return;
	}

	if (asn1_get_tag(contentHints->tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Expected SEQUENCE for ContentHints\n");
		exit(EXIT_FAILURE);
	}
	size_t len = contentHints->length;

	struct memfp mp;
	memfp_open(&mp, contentHints->value, contentHints->length);
	mseek(&mp, 0, SEEK_SET);
	long start_pos = mtell(&mp);

	ASN1Object obj;
	if (asn1_load_tag(&mp, &obj, ASN1_TAG_UTF8_STRING) == 0) {
		printf("      contentDescription: ");
		asn1_print_printable_string(&obj);
		printf("\n");
	}

	if ((size_t)(mtell(&mp) - start_pos) == len) {
		fprintf(stderr, "Warning: Missing contentType\n");
		memfp_close(&mp);
		return;
	}

	if (asn1_load(&mp, &obj) == 0) {
		printf("      contentType: ");
		asn1_print_oid(&obj);
		printf("\n");
	} else {
		fprintf(stderr,
			"Error: Expected OBJECT IDENTIFIER for contentType\n");
		exit(EXIT_FAILURE);
	}

	memfp_close(&mp);
}

static void print_smime_capability(const ASN1Object *smimeCap)
{
	/* RFC 8551 
	 * SMIMECapability ::= SEQUENCE {
	 * 	capabilityID OBJECT IDENTIFIER,
	 * 	parameters ANY DEFINED BY capabilityID OPTIONAL }
	 */
	printf("      ");
	struct memfp mp;
	memfp_open(&mp, smimeCap->value, smimeCap->length);
	mseek(&mp, 0, SEEK_SET);
	long start_pos = mtell(&mp);

	ASN1Object obj;
	if (asn1_load(&mp, &obj) == 0) {
		asn1_print_oid(&obj);
	} else {
		fprintf(stderr,
			"Error: Expected OBJECT IDENTIFIER for capabilityID\n");
		exit(EXIT_FAILURE);
	}

	/* parameters */
	if ((size_t)(mtell(&mp) - start_pos) < smimeCap->length) {
		printf(": ");
	}
	int oid_type = asn1_get_oid_type(&obj);

	while ((size_t)(mtell(&mp) - start_pos) < smimeCap->length) {
		switch (oid_type) {
		case OID_TYPES_rc2CBC:
			if (asn1_load_tag(&mp, &obj, ASN1_TAG_INTEGER) == 0) {
				asn1_print_integer(&obj);
				if ((size_t)(mtell(&mp) - start_pos) <
				    smimeCap->length) {
					printf(", ");
				}
			} else {
				fprintf(stderr,
					"Error: Failed to load parameter for rc2CBC\n");
				exit(EXIT_FAILURE);
			}
			break;
		default:
			fprintf(stderr, "Error: Unsupported capabilityID\n");
			exit(EXIT_FAILURE);
		}
	}

	memfp_close(&mp);
}

static void print_smime_capabilities(const ASN1Object *smimeCaps)
{
	/* RFC 8551: SMIMECapabilities ::= SEQUENCE OF SMIMECapability */
	if (asn1_get_tag(smimeCaps->tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr,
			"Error: Expected SEQUENCE for SMIMECapabilities\n");
		exit(EXIT_FAILURE);
	}

	struct memfp mp;
	memfp_open(&mp, smimeCaps->value, smimeCaps->length);
	mseek(&mp, 0, SEEK_SET);
	long start_pos = mtell(&mp);

	ASN1Object obj;
	while ((size_t)(mtell(&mp) - start_pos) < smimeCaps->length) {
		if (asn1_load(&mp, &obj) == 0) {
			print_smime_capability(&obj);
			printf("\n");
		} else {
			fprintf(stderr,
				"Error: Failed to load SMIMECapability\n");
			exit(EXIT_FAILURE);
		}
	}

	memfp_close(&mp);
}

static void print_Attribute(const ASN1Object *attr)
{
	/* Attribute ::= SEQUENCE {
		type   OBJECT IDENTIFIER,
		values SET OF AttributeValue }
	*/
	if (asn1_get_tag(attr->tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Expected SEQUENCE for Attribute\n");
		exit(EXIT_FAILURE);
	}

	struct memfp mp;
	memfp_open(&mp, attr->value, attr->length);
	mseek(&mp, 0, SEEK_SET);

	int oid_type;
	ASN1Object obj;
	if (asn1_load(&mp, &obj) == 0) {
		printf("    ");
		oid_type = asn1_get_oid_type(&obj);
		asn1_print_oid(&obj);
	} else {
		fprintf(stderr, "Error: Expected OBJECT IDENTIFIER for type\n");
		exit(EXIT_FAILURE);
	}

	if (asn1_get_tag(mgetc(&mp)) != ASN1_TAG_SET) {
		fprintf(stderr,
			"Error: Expected SET OF AttributeValue for values\n");
		exit(EXIT_FAILURE);
	}
	asn1_get_length(&mp); /* Advance to content */

	if (asn1_load(&mp, &obj) != 0) {
		fprintf(stderr,
			"Error: Failed to load AttributeValue for values\n");
		exit(EXIT_FAILURE);
	}

	switch (oid_type) {
	case OID_TYPES_id_contentType:
		printf(": ");
		asn1_print_oid(&obj);
		break;
	case OID_TYPES_id_signingTime:
		printf(": ");
		/* SigningTime ::= Time */
		asn1_print_time_string(&obj);
		break;
	case OID_TYPES_id_aa_CMSAlgorithmProtection:
		printf("\n");
		print_CMSAlgorithmProtection(&obj);
		break;
	case OID_TYPES_id_messageDigest:
		printf("\n");
		if (asn1_get_tag(obj.tag) == ASN1_TAG_OCTET_STRING) {
			asn1_print_octet_string(&obj);
		} else {
			fprintf(stderr,
				"Error: Expected OCTET STRING for messageDigest\n");
			exit(EXIT_FAILURE);
		}
		break;
	case OID_TYPES_id_aa_contentHint:
		printf("\n");
		print_ContentHints(&obj);
		break;
	case OID_TYPES_smimeCapabilities:
		printf("\n");
		print_smime_capabilities(&obj);
		break;
	default:
		printf("\n");
		printf("Unknown OID:\n");
		X509_dump8(obj.value, obj.length);
		break;
	}

	printf("\n");

	memfp_close(&mp);
}

static void print_Attributes(const ASN1Object *signedAttrs)
{
	/* SignedAttributes ::= SET OF Attribute */
	if (asn1_get_tag(signedAttrs->tag) != ASN1_TAG_CONTEXT_SPECIFIC_0) {
		fprintf(stderr, "Error: Expected [0] for SignedAttributes\n");
		exit(EXIT_FAILURE);
	}

	if (asn1_is_constructed(signedAttrs->tag)) { /* Expected IMPLICIT */
#ifdef DEBUG
		/* It is not typical */
		fprintf(stderr,
			"Warning: [0] IMPLICIT SignedAttribute has C/P set\n");
#endif
	}
	/* SET is saved by IMPLICIT tagging */

	size_t len = signedAttrs->length;
	struct memfp mp;
	memfp_open(&mp, signedAttrs->value, signedAttrs->length);
	mseek(&mp, 0, SEEK_SET);

	ASN1Object attr_obj;
	while (len) {
		long start_pos = mtell(&mp);
		if (asn1_load(&mp, &attr_obj) == 0) {
			print_Attribute(&attr_obj);
		} else {
			fprintf(stderr, "Error: Failed to load Attribute\n");
			exit(EXIT_FAILURE);
		}

		len -= mtell(&mp) - start_pos;
	}

	memfp_close(&mp);
}

static void print_SignerInfo(const ASN1Object *si)
{
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

	if (asn1_get_tag(si->tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Expected SEQUENCE for SignerInfo\n");
		exit(EXIT_FAILURE);
	}

	struct memfp mp;
	memfp_open(&mp, si->value, si->length);
	mseek(&mp, 0, SEEK_SET);
	long start_pos = mtell(&mp);

	struct CMS_SignerInfo si_data;
	if (asn1_load_tag(&mp, &si_data.version, ASN1_TAG_INTEGER) == 0) {
		printf("  version: %u\n", si_data.version.value[0]);
	} else {
		fprintf(stderr, "Error: Expected INTEGER for version\n");
		exit(EXIT_FAILURE);
	}

	printf("  sid-");
	if (asn1_load(&mp, &si_data.sid) == 0) {
		print_sid(&si_data.sid);

	} else {
		fprintf(stderr, "Error: Expected SignerIdentifier\n");
	}

	printf("\n");

	printf("  digestAlgorithm: ");
	if (asn1_load(&mp, &si_data.digestAlgorithm) == 0) {
		X509_print_AlgorithmIdentifier(&si_data.digestAlgorithm);
	} else {
		fprintf(stderr, "Error: Expected DigestAlgorithmIdentifier\n");
		exit(EXIT_FAILURE);
	}

	printf("\n");

	printf("  signedAttrs:");
	if (asn1_get_tag(mpeekc(&mp)) == ASN1_TAG_CONTEXT_SPECIFIC_0) {
		printf("\n");
		if (asn1_load_tag(&mp, &si_data.signedAttrs,
				  ASN1_TAG_CONTEXT_SPECIFIC_0) == 0) {
			print_Attributes(&si_data.signedAttrs);
		} else {
			fprintf(stderr, "Error: Expected SignedAttributes\n");
			exit(EXIT_FAILURE);
		}
	} else {
		printf(" not present\n");
	}

	printf("  signatureAlgorithm: ");
	if (asn1_load(&mp, &si_data.signatureAlgorithm) == 0) {
		X509_print_AlgorithmIdentifier(&si_data.signatureAlgorithm);
	} else {
		fprintf(stderr,
			"Error: Expected SignatureAlgorithmIdentifier\n");
		exit(EXIT_FAILURE);
	}

	printf("\n");

	printf("  signature:\n");
	if (asn1_load_tag(&mp, &si_data.signature, ASN1_TAG_OCTET_STRING) ==
	    0) {
		asn1_print_octet_string(&si_data.signature);
	} else {
		fprintf(stderr, "Error: Expected SignatureValue\n");
		exit(EXIT_FAILURE);
	}

	printf("\n");

	if ((size_t)mtell(&mp) < (size_t)start_pos + si->length) {
		printf("  unsignedAttrs:");
		if (asn1_get_tag(mpeekc(&mp)) == ASN1_TAG_CONTEXT_SPECIFIC_1) {
			printf("\n");
			if (asn1_load_tag(&mp, &si_data.unsignedAttrs,
					  ASN1_TAG_CONTEXT_SPECIFIC_1) == 0) {
				print_Attributes(&si_data.unsignedAttrs);
			} else {
				fprintf(stderr,
					"Error: Expected UnsignedAttributes\n");
				exit(EXIT_FAILURE);
			}
		} else {
			printf(" not present\n");
		}
	}

	memfp_close(&mp);
}

static void print_signerInfos(const ASN1Object *signerInfos)
{
	/* SignerInfos ::= SET OF SignerInfo */
	if (asn1_get_tag(signerInfos->tag) != ASN1_TAG_SET) {
		fprintf(stderr, "Error: Expected SET for SignerInfos\n");
		exit(EXIT_FAILURE);
	}

	struct memfp mp;
	memfp_open(&mp, signerInfos->value, signerInfos->length);
	mseek(&mp, 0, SEEK_SET);

	ASN1Object si_obj;
	size_t len = signerInfos->length;
	while (len) {
		long start_pos = mtell(&mp);
		if (asn1_load(&mp, &si_obj) == 0) {
			print_SignerInfo(&si_obj);
		} else {
			fprintf(stderr, "Error: Expected SignerInfo\n");
			exit(EXIT_FAILURE);
		}
		len -= (mtell(&mp) - start_pos);
	}

	memfp_close(&mp);
}

static void print_CMS_SignedData(const struct CMS_SignedData *sd)
{
	if (sd->version.length == 1)
		printf("version: %u\n", sd->version.value[0]);
	else
		printf("version: (length: %zu)\n", sd->version.length);

	printf("digestAlgorithms: ");
	print_digestAlgorithms(&sd->digestAlgorithms);
	printf("\n");

	printf("encapContentInfo:\n");
	print_encapContentInfo(&sd->encapContentInfo);
	printf("\n");

	if (sd->certificates.length) {
		printf("certificates: present (%zu bytes)\n",
		       sd->certificates.length);
	} else {
		printf("certificates: not present\n");
	}

	if (sd->crls.length) {
		printf("crls: present (%zu bytes)\n", sd->crls.length);
	} else {
		printf("crls: not present\n");
	}

	printf("signerInfos:\n");
	print_signerInfos(&sd->signerInfos);
	printf("\n");
}

/** oid.h -- header file for object identifiers */
#ifndef OID_H
#define OID_H

#include <stdio.h>
#include <stdint.h>

#define OID_MAX_LEN 16
typedef struct {
	uint32_t oid_len;
	uint32_t oid[OID_MAX_LEN];
	const char *desc;
} OID;

/* Index into oid_database[]. Add a name here and a matching row there. */
enum oid_type {
	OID_TYPES_member_body,
	OID_TYPES_id_ecPublicKey,
	OID_TYPES_secp256r1,
	OID_TYPES_ecdsa_with_SHA256,
	OID_TYPES_rsadsi,
	OID_TYPES_rsaEncryption,
	OID_TYPES_sha1WithRSAEncryption,
	OID_TYPES_sha256WithRSAEncryption,
	OID_TYPES_id_aa_contentHint,
	OID_TYPES_id_data,
	OID_TYPES_id_signedData,
	OID_TYPES_id_contentType,
	OID_TYPES_id_messageDigest,
	OID_TYPES_id_signingTime,
	OID_TYPES_id_counterSignature,
	OID_TYPES_smimeCapabilities,
	OID_TYPES_pkcs_9_ub_emailAddress,
	OID_TYPES_pkcs_9_ub_unstructuredName,
	OID_TYPES_pkcs_9_at_challengePassword,
	OID_TYPES_pkcs_9_at_extensionRequest,
	OID_TYPES_id_aa_CMSAlgorithmProtection,
	OID_TYPES_rc2CBC,
	OID_TYPES_des_EDE3_CBC,
	OID_TYPES_desCBC,
	OID_TYPES_appleSecurity_6_86,
	OID_TYPES_jurisdictionOfIncorporationLocalityName,
	OID_TYPES_jurisdictionOfIncorporationStateOrProvinceName,
	OID_TYPES_jurisdictionOfIncorporationCountryName,
	OID_TYPES_embedded_scts,
	OID_TYPES_id_pe_authorityInfoAccess,
	OID_TYPES_id_qt_cps,
	OID_TYPES_id_qt_unotice,
	OID_TYPES_id_kp_serverAuth,
	OID_TYPES_id_kp_clientAuth,
	OID_TYPES_id_ad_ocsp,
	OID_TYPES_id_ad_caIssuers,
	OID_TYPES_id_at_commonName,
	OID_TYPES_id_at_serialNumber,
	OID_TYPES_id_at_countryName,
	OID_TYPES_id_at_localityName,
	OID_TYPES_id_at_stateOrProvinceName,
	OID_TYPES_id_at_organizationName,
	OID_TYPES_id_at_organizationalUnitName,
	OID_TYPES_id_at_businessCategory,
	OID_TYPES_id_at_organizationIdentifier,
	OID_TYPES_id_ce_subjectDirectoryAttributes,
	OID_TYPES_id_ce_subjectKeyIdentifier,
	OID_TYPES_id_ce_keyUsage,
	OID_TYPES_id_ce_subjectAltName,
	OID_TYPES_id_ce_basicConstraints,
	OID_TYPES_id_ce_cRLDistributionPoints,
	OID_TYPES_id_ce_certificatePolicies,
	OID_TYPES_id_ce_anyPolicy,
	OID_TYPES_id_ce_authorityKeyIdentifier,
	OID_TYPES_id_ce_extKeyUsage,
	OID_TYPES_id_aes128_CBC,
	OID_TYPES_id_aes192_CBC,
	OID_TYPES_id_aes256_CBC,
	OID_TYPES_id_sha256,
	OID_TYPES_ev_ssl_certificates_2_1,
	OID_TYPES_ev_guidelines,
	OID_TYPES_domain_validated,
	OID_TYPES_organization_validated,
	OID_TYPES_COUNT
};

#define OID_TYPES_UNKNOWN -1

int lookup_oid(const uint32_t oid[], uint32_t oid_len);
void print_oid(const uint32_t oid[], uint32_t oid_len);
int print_oid_desc(int oid_type);

extern const OID oid_database[OID_TYPES_COUNT];

#endif /* OID_H */

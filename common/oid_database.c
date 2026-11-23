/* oid_database.c - table of known OIDs, indexed by enum oid_type */
#include "oid.h"

/* clang-format off */
const OID oid_database[OID_TYPES_COUNT] = {
	[OID_TYPES_member_body]       = { .oid_len = 2, .oid = { 1, 2 }, .desc = "member-body" },
	[OID_TYPES_id_ecPublicKey]    = { 6, { 1, 2, 840, 10045, 2, 1 }, "id-ecPublicKey" }, /* RFC 5480 */
	[OID_TYPES_secp256r1]         = { 7, { 1, 2, 840, 10045, 3, 1, 7 }, "secp256r1" }, /* RFC 5480 */
	[OID_TYPES_ecdsa_with_SHA256] = { 7, { 1, 2, 840, 10045, 4, 3, 2 }, "ecdsa-with-SHA256" }, /* RFC 5758 */
	[OID_TYPES_rsadsi]            = { 4, { 1, 2, 840, 113549 }, "rsadsi" }, /* X.509 */
	[OID_TYPES_rsaEncryption]     = { 7, { 1, 2, 840, 113549, 1, 1, 1 }, "rsaEncryption" }, /* RFC 4055 */
	[OID_TYPES_sha1WithRSAEncryption] = { 7, { 1, 2, 840, 113549, 1, 1, 5 }, "sha1WithRSAEncryption" },
	[OID_TYPES_id_aa_contentHint] = { 9, { 1, 2, 840, 113549, 1, 9, 16, 2, 4 }, "id-aa-contentHint" }, /* RFC 2634 */

	/* RFC 5652 CMS/PKCS #7 */
	[OID_TYPES_id_data]             = { 7, { 1, 2, 840, 113549, 1, 7, 1 }, "id_data" },
	[OID_TYPES_id_signedData]       = { 7, { 1, 2, 840, 113549, 1, 7, 2 }, "id_signedData" },
	[OID_TYPES_id_contentType]      = { 7, { 1, 2, 840, 113549, 1, 9, 3 }, "id_contentType" },
	[OID_TYPES_id_messageDigest]    = { 7, { 1, 2, 840, 113549, 1, 9, 4 }, "id_messageDigest" },
	[OID_TYPES_id_signingTime]      = { 7, { 1, 2, 840, 113549, 1, 9, 5 }, "id_signingTime" },
	[OID_TYPES_id_counterSignature] = { 7, { 1, 2, 840, 113549, 1, 9, 6 }, "id_counterSignature" },

	[OID_TYPES_smimeCapabilities] = { 7, { 1, 2, 840, 113549, 1, 9, 15 }, "smimeCapabilities" }, /* RFC 8551 */

	/* PKCS #9 */
	[OID_TYPES_pkcs_9_ub_emailAddress]      = { 7, { 1, 2, 840, 113549, 1, 9, 1 }, "pkcs-9-ub-emailAddress" },
	[OID_TYPES_pkcs_9_ub_unstructuredName]  = { 7, { 1, 2, 840, 113549, 1, 9, 2 }, "pkcs-9-ub-unstructuredName" },
	[OID_TYPES_pkcs_9_at_challengePassword] = { 7, { 1, 2, 840, 113549, 1, 9, 7 }, "pkcs-9-at-challengePassword" },
	[OID_TYPES_pkcs_9_at_extensionRequest]  = { 7, { 1, 2, 840, 113549, 1, 9, 14 }, "pkcs-9-at-extensionRequest" },

	/* RFC 6211 */
	[OID_TYPES_id_aa_CMSAlgorithmProtection] = { 7, { 1, 2, 840, 113549, 1, 9, 52 }, "id-aa-CMSAlgorithmProtection" },

	/* RFC 8018 */
	[OID_TYPES_rc2CBC]       = { 6, { 1, 2, 840, 113549, 3, 2 }, "rc2CBC" },
	[OID_TYPES_des_EDE3_CBC] = { 6, { 1, 2, 840, 113549, 3, 7 }, "des-EDE3-CBC" },

	/* Apple Security */
	[OID_TYPES_appleSecurity_6_86] = { 7, { 1, 2, 840, 113635, 100, 6, 86 }, "appleSecurity(6)?(86)" },

	/* 311 - Microsoft */
	[OID_TYPES_jurisdictionOfIncorporationLocalityName]        = { 11, { 1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 1 }, "jurisdictionOfIncorporationLocalityName" },
	[OID_TYPES_jurisdictionOfIncorporationStateOrProvinceName] = { 11, { 1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 2 }, "jurisdictionOfIncorporationStateOrProvinceName" },
	[OID_TYPES_jurisdictionOfIncorporationCountryName]         = { 11, { 1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3 }, "jurisdictionOfIncorporationCountryName" },

	[OID_TYPES_sha256WithRSAEncryption] = { 7, { 1, 2, 840, 113549, 1, 1, 11 }, "sha256WithRSAEncryption" }, /* RFC 4055 */
	[OID_TYPES_embedded_scts]           = { 10, { 1, 3, 6, 1, 4, 1, 11129, 2, 4, 2 }, "embedded-scts" }, /* RFC 6962 */

	/* RFC 5280 (X.509 2008)*/
	[OID_TYPES_id_pe_authorityInfoAccess] = { 9, { 1, 3, 6, 1, 5, 5, 7, 1, 1 }, "id-pe-authorityInfoAccess" },
	[OID_TYPES_id_qt_cps]                 = { 9, { 1, 3, 6, 1, 5, 5, 7, 2, 1 }, "id-qt-cps" },
	[OID_TYPES_id_qt_unotice]             = { 9, { 1, 3, 6, 1, 5, 5, 7, 2, 2 }, "id-qt-unotice" },
	[OID_TYPES_id_kp_serverAuth]          = { 9, { 1, 3, 6, 1, 5, 5, 7, 3, 1 }, "id-kp-serverAuth" },
	[OID_TYPES_id_kp_clientAuth]          = { 9, { 1, 3, 6, 1, 5, 5, 7, 3, 2 }, "id-kp-clientAuth " },
	[OID_TYPES_id_ad_ocsp]                = { 9, { 1, 3, 6, 1, 5, 5, 7, 48, 1 }, "id-ad-ocsp" },
	[OID_TYPES_id_ad_caIssuers]           = { 9, { 1, 3, 6, 1, 5, 5, 7, 48, 2 }, "id-ad-caIssuers" },

	/* RFC 8018 */
	[OID_TYPES_desCBC] = { 6, { 1, 3, 14, 3, 2, 7 }, "desCBC" },

	/* X.520 */
	[OID_TYPES_id_at_commonName]             = { 4, { 2, 5, 4, 3 }, "id-at-commonName" },
	[OID_TYPES_id_at_serialNumber]           = { 4, { 2, 5, 4, 5 }, "id-at-serialNumber" },
	[OID_TYPES_id_at_countryName]            = { 4, { 2, 5, 4, 6 }, "id-at-countryName" },
	[OID_TYPES_id_at_localityName]           = { 4, { 2, 5, 4, 7 }, "id-at-localityName" },
	[OID_TYPES_id_at_stateOrProvinceName]    = { 4, { 2, 5, 4, 8 }, "id-at-stateOrProvinceName" },
	[OID_TYPES_id_at_organizationName]       = { 4, { 2, 5, 4, 10 }, "id-at-organizationName" },
	[OID_TYPES_id_at_organizationalUnitName] = { 4, { 2, 5, 4, 11 }, "id-at-organizationalUnitName" },
	[OID_TYPES_id_at_businessCategory]       = { 4, { 2, 5, 4, 15 }, "id-at-businessCategory" },
	[OID_TYPES_id_at_organizationIdentifier] = { 4, { 2, 5, 4, 97 }, "id-at-organizationIdentifier" },

	/* X.509 RFC5280 */
	[OID_TYPES_id_ce_subjectDirectoryAttributes] = { 4, { 2, 5, 29, 9 }, "id-ce-subjectDirectoryAttributes" },
	[OID_TYPES_id_ce_subjectKeyIdentifier]       = { 4, { 2, 5, 29, 14 }, "id-ce-subjectKeyIdentifier" },
	[OID_TYPES_id_ce_keyUsage]                   = { 4, { 2, 5, 29, 15 }, "id-ce-keyUsage" },
	[OID_TYPES_id_ce_subjectAltName]             = { 4, { 2, 5, 29, 17 }, "id-ce-subjectAltName" },
	[OID_TYPES_id_ce_basicConstraints]           = { 4, { 2, 5, 29, 19 }, "id-ce-basicConstraints" },
	[OID_TYPES_id_ce_cRLDistributionPoints]      = { 4, { 2, 5, 29, 31 }, "id-ce-cRLDistributionPoints" },
	[OID_TYPES_id_ce_certificatePolicies]        = { 4, { 2, 5, 29, 32 }, "id-ce-certificatePolicies" },
	[OID_TYPES_id_ce_anyPolicy]                  = { 5, { 2, 5, 29, 32, 0 }, "id-ce-anyPolicy" },
	[OID_TYPES_id_ce_authorityKeyIdentifier]     = { 4, { 2, 5, 29, 35 }, "id-ce-authorityKeyIdentifier" },
	[OID_TYPES_id_ce_extKeyUsage]                = { 4, { 2, 5, 29, 37 }, "id-ce-extKeyUsage" },

	/* RFC 3565 */
	[OID_TYPES_id_aes128_CBC] = { 9, { 2, 16, 840, 1, 101, 3, 4, 1, 2 }, "id-aes128-CBC" },
	[OID_TYPES_id_aes192_CBC] = { 9, { 2, 16, 840, 1, 101, 3, 4, 1, 22 }, "id-aes192-CBC" },
	[OID_TYPES_id_aes256_CBC] = { 9, { 2, 16, 840, 1, 101, 3, 4, 1, 42 }, "id-aes256-CBC" },

	/* NIST */
	[OID_TYPES_id_sha256] = { 9, { 2, 16, 840, 1, 101, 3, 4, 2, 1 }, "id_sha256" },

	/* Digicert (11412) */
	[OID_TYPES_ev_ssl_certificates_2_1] = { 7, { 2, 16, 840, 1, 114412, 2, 1 }, "ev-ssl-certificates(2) 1" },

	[OID_TYPES_ev_guidelines]          = { 5, { 2, 23, 140, 1, 1 }, "ev-guidelines" },
	[OID_TYPES_domain_validated]       = { 6, { 2, 23, 140, 1, 2, 1 }, "domain-validated" },
	[OID_TYPES_organization_validated] = { 6, { 2, 23, 140, 1, 2, 2 }, "organization-validated" },
};
/* clang-format on */

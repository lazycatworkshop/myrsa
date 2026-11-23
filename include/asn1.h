/** asn1.h - header file for ASN1 */
#ifndef ASN1_H
#define ASN1_H

#include <stdint.h>
#include "memfp.h"

#define ASN1_MAX_STRING_LENGTH 256

#pragma pack(push, 1)
typedef struct {
	uint8_t tag : 5;
	uint8_t constructed : 1;
	uint8_t class : 2;
} asn1_id_octet;

#define ASN1_TAG_MASK 0xdf /* Take out P/C flag */
#define ASN1_C_P_MASK 0x20
#define ASN1_CLASS_MASK 0xc0
#define ASN1_CLASS_CONTEXT 0x80

typedef struct {
	uint8_t length : 7;
	uint8_t long_form : 1;
} asn1_length_octet;
#pragma pack(pop)

#define ASN1_LONG_FORM_MASK 0x80
#define ASN1_LENGTH_MASK 0x7f
#define ASN1_INDEFINITE_FORM 0x80
#define ASN1_INDEFINITE_LENGTH 0xffff

#define ASN1_BOOLEAN_TRUE 0xff
#define ASN1_BOOLEAN_FALSE 0x00

/* NOTE: TAG here refers to the ASN.1 tag number without the constructed/
 * primitive bit.
*/
enum ASN1_TAG_NUMBER {
	ASN1_TAG_EOC = 0,
	ASN1_TAG_BOOLEAN = 1,
	ASN1_TAG_INTEGER = 2,
	ASN1_TAG_BIT_STRING = 3,
	ASN1_TAG_OCTET_STRING = 4,
	ASN1_TAG_NULL = 5,
	ASN1_TAG_OBJECT_IDENTIFIER = 6,
	ASN1_TAG_OBJECT_DESCRIPTOR = 7,
	ASN1_TAG_EXTERNAL = 8,
	ASN1_TAG_REAL = 9,
	ASN1_TAG_ENUMERATED = 10,
	ASN1_TAG_EMBEDDED_PDV = 11,
	ASN1_TAG_UTF8_STRING = 12,
	ASN1_TAG_RELATIVE_OID = 13,
	ASN1_TAG_TIME = 14,
	ASN1_TAG_RESERVED = 15,
	ASN1_TAG_SEQUENCE = 16,
	ASN1_TAG_SET = 17,
	ASN1_TAG_NUMERIC_STRING = 18,
	ASN1_TAG_PRINTABLE_STRING = 19,
	ASN1_TAG_T61_STRING = 20,
	ASN1_TAG_VID_STRING = 21,
	ASN1_TAG_IA5_STRING = 22,
	ASN1_TAG_UTC = 23,
	ASN1_TAG_GENERALIZED_TIME = 24,
	ASN1_TAG_GRAPHIC_STRING = 25,
	ASN1_TAG_VISIBLE_STRING = 26,
	ASN1_TAG_GENERAL_STRING = 27,
	ASN1_TAG_UNIVERSAL_STRING = 28,
	ASN1_TAG_CHARACTER_STRING = 29,
	ASN1_TAG_BMP_STRING = 30,
	ASN1_TAG_DATE = 31,
	ASN1_TAG_TIME_OF_DAY = 32,
	ASN1_TAG_DATE_TIME = 33,
	ASN1_TAG_DURATION = 34,
	ASN1_TAG_OID_IRI = 35,
	ASN1_TAG_RELATIVE_OID_IRI = 36,
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

#pragma pack(push, 1)
typedef struct {
	uint8_t tag;
	size_t length;
	const uint8_t *value;

} ASN1Object;
#pragma pack(pop)

/** 
 * asn1_get_tag - Get the ASN.1 tag from the identifier octet.
 *
 * @param identifier The ASN.1 identifier octet.
 * @return The ASN.1 tag with the constructed bit cleared.
 */
static inline enum ASN1_TAG_NUMBER asn1_get_tag(uint8_t identifier)
{
	return (enum ASN1_TAG_NUMBER)(identifier & ASN1_TAG_MASK);
}

static inline uint8_t asn1_is_constructed(uint8_t identifier)
{
	return (identifier & ASN1_C_P_MASK) != 0;
}

static inline uint8_t asn1_is_indefinite_form(uint8_t length_octet)
{
	return length_octet == ASN1_INDEFINITE_FORM;
}

static inline uint8_t asn1_is_short_form(uint8_t length_octet)
{
	return (length_octet & ASN1_LONG_FORM_MASK) == 0;
}

static inline uint8_t asn1_is_long_form(uint8_t length_octet)
{
	return (length_octet & ASN1_LONG_FORM_MASK) &&
	       (length_octet & ASN1_LENGTH_MASK);
}

int asn1_get_oid(const uint8_t octets[], int length, uint32_t oid[],
		 int *oid_length);

static inline int asn1_is_true(uint8_t boolean_octet)
{
	return boolean_octet == ASN1_BOOLEAN_TRUE;
}

static inline int asn1_is_implicit(uint8_t identifier)
{
	/* Context-specific class, primitive */
	return (identifier & (ASN1_CLASS_MASK | ASN1_C_P_MASK)) ==
	       ASN1_CLASS_CONTEXT;
}

/** 
 * asn1_get_length_bytes - Get the number of length bytes for the given length
 * octet.
 *
 * @param length_octet The first length octet.
 * @return The number of length bytes.
 */
static inline int asn1_get_length_bytes(uint8_t length_octet)
{
	if (asn1_is_indefinite_form(length_octet)) {
		return 0;
	}
	if (asn1_is_long_form(length_octet)) {
		return length_octet & ASN1_LENGTH_MASK;
	}
	return 0; /* Short form */
}

int asn1_get_length(struct memfp *mp);
int asn1_load(struct memfp *mp, ASN1Object *asn1);
int asn1_load_tag(struct memfp *mp, ASN1Object *asn1, uint8_t tag);
int asn1_get_oid_type(const ASN1Object *asn1);
void asn1_print_oid(const ASN1Object *asn1);
void asn1_print_printable_string(const ASN1Object *obj);
void asn1_print_time_string(const ASN1Object *obj);
void asn1_print_bit_string(const ASN1Object *obj);
void asn1_print_integer(const ASN1Object *obj);
void asn1_print_octet_string(const ASN1Object *obj);

#endif /* ASN1_H */

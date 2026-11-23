/* asn1parser.c - This is a program that takes in a DER file and show the
 * content in ASN.1 syntax.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <assert.h>

#include "asn1.h"

#define MAX_STRING_LENGTH 128

static enum {
	VERBOSE_LEVEL_NONE,
	VERBOSE_LEVEL_INFO,
	VERBOSE_LEVEL_DEBUG
} verbose_level = VERBOSE_LEVEL_NONE;

void print_usage(const char *progname)
{
	fprintf(stderr, "Usage: %s -f <file> [-v]\n", progname);
}

static int parse_asn1(FILE *fp, int depth, int length);

int main(int argc, char *argv[])
{
	int ret = EXIT_SUCCESS;
	int opt;
	const char *filename = NULL;
	FILE *fp = NULL;
	while ((opt = getopt(argc, argv, "f:v")) != -1) {
		switch (opt) {
		case 'f':
			filename = optarg;
			break;
		case 'v':
			verbose_level++;
			break;
		default:
			print_usage(argv[0]);
			ret = EXIT_FAILURE;
			goto out;
		}
	}
	if (!filename) {
		print_usage(argv[0]);
		ret = EXIT_FAILURE;
		goto out;
	}
	fp = fopen(filename, "rb");
	if (!fp) {
		fprintf(stderr, "Failed to open file '%s': %s\n", filename,
			strerror(errno));
		ret = EXIT_FAILURE;
		goto out;
	}

	fseek(fp, 0, SEEK_END);
	long filesize = ftell(fp);
	rewind(fp);
	if (filesize <= 0) {
		fprintf(stderr,
			"Failed to determine file size or file is empty\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	/* Quick check for DER file */
	if (filesize < 2) {
		fprintf(stderr, "File is too small to be a valid DER file\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	int c = fgetc(fp);
	if (c == EOF) {
		fprintf(stderr, "Failed to read the first byte of the file\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	rewind(fp);

	/* Dump the raw content of the file */
	if (verbose_level >= VERBOSE_LEVEL_DEBUG) {
		printf("File size: %ld\n", filesize);
		int j = 0;
		while ((c = getc(fp)) != EOF) {
			if (j % 16 == 0)
				printf("%04ld: ", ftell(fp) - 1);
			printf("%02x ", c);
			if (++j % 16 == 0)
				printf("\n");
		}
		printf("\n");
		rewind(fp);
	}

	ret = parse_asn1(fp, 0, filesize);

out:
	if (fp)
		fclose(fp);

	return ret;
}

static int print_tag(enum ASN1_TAG_NUMBER tag, int depth);
static int parse_length(FILE *fp);
static void parse_octet_string(FILE *fp, int length);
static void parse_boolean(FILE *fp);
static void parse_printable_string(FILE *fp, int length);
static void parse_object_identifier(FILE *fp, int length);
static void parse_bit_stream(FILE *fp, int length);

/** 
 * parse_asn1 - Parses ASN.1 structure
 * @fp: File pointer to the DER file
 * @depth: Current depth in the ASN.1 structure
 * @length: Length of the current ASN.1 element
 *
 * Returns 0 on success, non-zero on failure
 */

static int parse_asn1(FILE *fp, int depth, int length)
{
	while (length > 0) {
		int offset1 = ftell(fp);
		int offset2 = 0;

		/* Identifier octet */
		int id_octet = fgetc(fp);
		if (id_octet == EOF) {
			fprintf(stderr, "Failed to read identifier octet\n");
			return -1;
		}

		enum ASN1_TAG_NUMBER tag = asn1_get_tag((uint8_t)id_octet);
		print_tag(tag, depth);

		printf(" ");

		/* Length octet */
		int len = parse_length(fp);

		if (tag == ASN1_TAG_EOC) {
			length = 0; /* Complete current ASN.1 element */
			continue; /* Back to the previous depth */
		}

		if (asn1_is_constructed(id_octet)) {
			if (parse_asn1(fp, depth + 1, len) != 0)
				return -1;

			goto next;
		}

		switch (tag) {
		case ASN1_TAG_CONTEXT_SPECIFIC_0:
		case ASN1_TAG_CONTEXT_SPECIFIC_1:
		case ASN1_TAG_CONTEXT_SPECIFIC_2:
		case ASN1_TAG_CONTEXT_SPECIFIC_3:
		case ASN1_TAG_CONTEXT_SPECIFIC_4:
		case ASN1_TAG_CONTEXT_SPECIFIC_5:
		case ASN1_TAG_CONTEXT_SPECIFIC_6:
		case ASN1_TAG_CONTEXT_SPECIFIC_7:
			/* Implicit: without constructed flag set */
			parse_asn1(fp, depth + 1, len);
			goto next;
		default:
			break;
		}

		/* Content octets */
		if ((verbose_level > VERBOSE_LEVEL_NONE) && len > 0) {
			switch (tag) {
			case ASN1_TAG_BOOLEAN:
				parse_boolean(fp);
				break;
			case ASN1_TAG_BIT_STRING:
				parse_bit_stream(fp, len);
				break;
			case ASN1_TAG_NULL:
				/* NULL has no content octets */
				break;
			case ASN1_TAG_OBJECT_IDENTIFIER:
				parse_object_identifier(fp, len);
				break;
			case ASN1_TAG_UTF8_STRING:
			case ASN1_TAG_PRINTABLE_STRING:
				parse_printable_string(fp, len);
				break;
			case ASN1_TAG_T61_STRING:
			case ASN1_TAG_VID_STRING:
			case ASN1_TAG_IA5_STRING:
				/* Temporary */
				parse_printable_string(fp, len);
				break;
			default:
				parse_octet_string(fp, len);
				break;
			}

			printf("\n");
		} else {
			fseek(fp, len, SEEK_CUR);
		}

next:
		offset2 = ftell(fp);
		length -= (offset2 - offset1);
	}

	return 0;
}

static inline void print_indent(int depth)
{
	for (int i = 0; i < depth; i++)
		printf("-");
}

/* Unlisted tag values remain NULL; print_tag() must provide a fallback. */
static const char *const tag_name[256] = {
	"EOC", /* 0 */
	"BOOLEAN", /* 1 */
	"INTEGER", /* 2 */
	"BIT STRING", /* 3 */
	"OCTET STRING", /* 4 */
	"NULL", /* 5 */
	"OBJECT IDENTIFIER", /* 6 */
	"Object Descriptor", /* 7 */
	"EXTERNAL", /* 8 */
	"REAL", /* 9 */
	"ENUMERATED", /* 10 */
	"EMBEDDED PDV", /* 11 */
	"UTF8String", /* 12 */
	"RELATIVE-OID", /* 13 */
	"TIME", /* 14 */
	"Reserved", /* 15 */
	"SEQUENCE", /* 16 */
	"SET", /* 17 */
	"NumericString", /* 18 */
	"PrintableString", /* 19 */
	"T61String", /* 20 */
	"VideotexString",
	"IA5String", /* 22 */
	"UTCTime", /* 23 */
	"GeneralizedTime", /* 24 */
	"GraphicString", /* 25 */
	"VisibleString", /* 26 */
	"GeneralString", /* 27 */
	"UniversalString", /* 28 */
	"CHARACTER STRING", /* 29 */
	"BMPString", /* 30 */
	"DATE", /* 31 */
	"TIME-OF-DAY", /* 32 */
	"DATE-TIME", /* 33 */
	"DURATION", /* 34 */
	"OID-IRI", /* 35 */
	"RELATIVE-OID-IRI", /* 36 */
	"Unknown", /* 37 */
	"Unknown", /* 38 */
	"Unknown", /* 39 */
	"Unknown", /* 40 */
	"Unknown", /* 41 */
	"Unknown", /* 42 */
	"Unknown", /* 43 */
	"Unknown", /* 44 */
	"Unknown", /* 45 */
	"Unknown", /* 46 */
	"Unknown", /* 47 */
	"Unknown", /* 48 */
	"Unknown", /* 49 */
	"Unknown", /* 50 */
	"Unknown", /* 51 */
	"Unknown", /* 52 */
	"Unknown", /* 53 */
	"Unknown", /* 54 */
	"Unknown", /* 55 */
	"Unknown", /* 56 */
	"Unknown", /* 57 */
	"Unknown", /* 58 */
	"Unknown", /* 59 */
	"Unknown", /* 60 */
	"Unknown", /* 61 */
	"Unknown", /* 62 */
	"Unknown", /* 63 */
	"Unknown", /* 64 */
	"Unknown", /* 65 */
	"Unknown", /* 66 */
	"Unknown", /* 67 */
	"Unknown", /* 68 */
	"Unknown", /* 69 */
	"Unknown", /* 70 */
	"Unknown", /* 71 */
	"Unknown", /* 72 */
	"Unknown", /* 73 */
	"Unknown", /* 74 */
	"Unknown", /* 75 */
	"Unknown", /* 76 */
	"Unknown", /* 77 */
	"Unknown", /* 78 */
	"Unknown", /* 79 */
	"Unknown", /* 80 */
	"Unknown", /* 81 */
	"Unknown", /* 82 */
	"Unknown", /* 83 */
	"Unknown", /* 84 */
	"Unknown", /* 85 */
	"Unknown", /* 86 */
	"Unknown", /* 87 */
	"Unknown", /* 88 */
	"Unknown", /* 89 */
	"Unknown", /* 90 */
	"Unknown", /* 91 */
	"Unknown", /* 92 */
	"Unknown", /* 93 */
	"Unknown", /* 94 */
	"Unknown", /* 95 */
	"Unknown", /* 96 */
	"Unknown", /* 97 */
	"Unknown", /* 98 */
	"Unknown", /* 99 */
	"Unknown", /* 100 */
	"Unknown", /* 101 */
	"Unknown", /* 102 */
	"Unknown", /* 103 */
	"Unknown", /* 104 */
	"Unknown", /* 105 */
	"Unknown", /* 106 */
	"Unknown", /* 107 */
	"Unknown", /* 108 */
	"Unknown", /* 109 */
	"Unknown", /* 110 */
	"Unknown", /* 111 */
	"Unknown", /* 112 */
	"Unknown", /* 113 */
	"Unknown", /* 114 */
	"Unknown", /* 115 */
	"Unknown", /* 116 */
	"Unknown", /* 117 */
	"Unknown", /* 118 */
	"Unknown", /* 119 */
	"Unknown", /* 120 */
	"Unknown", /* 121 */
	"Unknown", /* 122 */
	"Unknown", /* 123 */
	"Unknown", /* 124 */
	"Unknown", /* 125 */
	"Unknown", /* 126 */
	"Unknown", /* 127 */
	"Context-specific 0", /* 128 */
	"Context-specific 1", /* 129 */
	"Context-specific 2", /* 130 */
	"Context-specific 3", /* 131 */
	"Context-specific 4", /* 132 */
	"Context-specific 5", /* 133 */
	"Context-specific 6", /* 134 */
	"Context-specific 7", /* 135 */
	"Context-specific 8", /* 136 */
};

/** 
 * print_tag - Print the ASN.1 tag with the specified depth.
 * 
 * @param tag The ASN.1 identifier octet less C/P.
 * @param depth The depth for indentation.
 * @return Always returns 0 for now.
 */
static int print_tag(enum ASN1_TAG_NUMBER tag, int depth)
{
	const char *name = tag_name[tag] ? tag_name[tag] : "Unknown";

	print_indent(depth);
	if (verbose_level == VERBOSE_LEVEL_DEBUG)
		printf("Tag: %02" PRIx8 " ", tag);
	printf("%s ", name);

	return 0;
}

static int parse_length(FILE *fp)
{
	/* Length octets */
	int length_bytes = 0;
	int length = getc(fp);
	if (asn1_is_indefinite_form(length) == 0) {
		if (asn1_is_long_form(length)) {
			length_bytes = asn1_get_length_bytes(length);
			length = 0;
			for (int i = 0; i < length_bytes; i++) {
				length = (length << 8) | getc(fp);
			}
		}
		printf("L = %d\n", length);
	} else {
		length = ASN1_INDEFINITE_LENGTH;
		printf("L = INDEFINITE\n");
	}

	return length;
}

static void parse_octet_string(FILE *fp, int length)
{
	for (int i = 0; i < length; i++) {
		int c = getc(fp);
		if (c == EOF) {
			fprintf(stderr,
				"Unexpected EOF while parsing OCTET STRING\n");
			exit(EXIT_FAILURE);
		}
		printf("%02x ", c);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}
}

static void parse_object_identifier(FILE *fp, int length)
{
	assert(length > 0);
	assert(length <= 16); /* Ensure we don't overflow the octets array */

	uint8_t octets[16];
	if (fread(octets, 1, length, fp) != (size_t)length) {
		fprintf(stderr,
			"Unexpected EOF while parsing OBJECT IDENTIFIER\n");
		exit(EXIT_FAILURE);
	}

	uint32_t oid[16 + 1]; /* One more than encoded subidentifiers */
	int oid_length = sizeof(oid) / sizeof(oid[0]);
	if (asn1_get_oid(octets, length, oid, &oid_length) != 0) {
		fprintf(stderr, "OBJECT IDENTIFIER too long\n");
		exit(EXIT_FAILURE);
	}

	printf("OID: ");
	for (int i = 0; i < oid_length; i++) {
		if (i > 0)
			printf(".");
		printf("%" PRIu32, oid[i]);
	}
	printf("\n");
}

static void parse_boolean(FILE *fp)
{
	int c = getc(fp);
	if (c == EOF) {
		fprintf(stderr, "Unexpected EOF while parsing BOOLEAN\n");
		exit(EXIT_FAILURE);
	}
	printf("BOOLEAN: %s\n", asn1_is_true(c) ? "TRUE" : "FALSE");
}

static void parse_printable_string(FILE *fp, int length)
{
	assert(length > 0);
	assert(length < MAX_STRING_LENGTH);
	char buffer[MAX_STRING_LENGTH];

	if (fread(buffer, 1, length, fp) != (size_t)length) {
		fprintf(stderr,
			"Unexpected EOF while parsing PrintableString\n");
		exit(EXIT_FAILURE);
	}
	buffer[length] = '\0';
	printf("%s\n", buffer);
}

static void parse_bit_stream(FILE *fp, int length)
{
	int unused_bits = getc(fp);
	if (unused_bits == EOF) {
		fprintf(stderr, "Unexpected EOF while parsing BIT STRING\n");
		exit(EXIT_FAILURE);
	}
	printf("Unused bits: %d\n", unused_bits);
	parse_octet_string(fp, length - 1);
}

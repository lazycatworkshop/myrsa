/** asn1parse.c - This is a program that takes in a DER file and show the
 * content in ASN.1 syntax.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#include "asn1.h"
#include "oid.h"

enum {
	VERBOSE_LEVEL_NONE,
	VERBOSE_LEVEL_INFO,
	VERBOSE_LEVEL_DEBUG
} verbose_level = VERBOSE_LEVEL_NONE;

#define MAX_STRING_LENGTH 128

int parse_asn1(FILE *fp, int depth, int length);

int main(int argc, char *argv[])
{
	int ret = EXIT_SUCCESS;
	int opt;
	char *filename = NULL;
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
			fprintf(stderr, "Usage: %s -f filename [-v]\n",
				argv[0]);
			ret = EXIT_FAILURE;
			goto out;
		}
	}

	if (filename == NULL) {
		fprintf(stderr, "Usage: %s -f filename [-v]\n", argv[0]);
		ret = EXIT_FAILURE;
		goto out;
	}

	fp = fopen(filename, "r");
	if (fp == NULL) {
		fprintf(stderr, "Error: Cannot open file %s: %s\n", filename,
			strerror(errno));
		ret = EXIT_FAILURE;
		goto out;
	}

	fseek(fp, 0, SEEK_END);
	long fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	if (!fsize) {
		fprintf(stderr, "Error: File is empty\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	int c = getc(fp);
	if (c == '-') { /* Encapsulate Boundary in PEM */
		fprintf(stderr, "Error: File is in PEM format\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	fseek(fp, 0, SEEK_SET);

	if (verbose_level >= VERBOSE_LEVEL_DEBUG) {
		printf("File size: %ld\n", fsize);
		int j = 0;
		while ((c = getc(fp)) != EOF) {
			if (j % 16 == 0)
				printf("%04ld: ", ftell(fp) - 1);
			printf("%02x ", c);
			if (++j % 16 == 0)
				printf("\n");
		}
		printf("\n");
		fseek(fp, 0, SEEK_SET);
	}

	ret = parse_asn1(fp, 0, fsize);

out:
	if (fp)
		fclose(fp);
	return ret;
}

int asn1_get_length(FILE *fp)
{
	/* Length octets */
	int length_bytes = 0;
	int length = getc(fp);
	if (length != ASN1_INDEFINITE_FORM) {
		if (length & 0x80) {
			length_bytes = length & 0x7f;
			length = 0;
			for (int i = 0; i < length_bytes; i++) {
				length = (length << 8) | getc(fp);
			}
		}
	} else {
		length = ASN1_INDEFINITE_LENGTH;
	}

	return length;
}

int print_tag(int code, int depth);
int print_object_identifier(FILE *fp, int length);
void print_octet_string(FILE *fp, int length);
void print_printable_string(FILE *fp, int length);
void get_time_string(FILE *fp, int length, char *time_str);
void print_utc_time(char *time_str);
void print_generalized_time(char *time_str);
void print_bit_string(FILE *fp, int length);

int parse_asn1(FILE *fp, int depth, int length)
{
	int ret = 1;
	int c;
	int tag;

	while (length) {
		int len = 0;
		int offset1, offset2 = 0;
		offset1 = ftell(fp);

		c = getc(fp);
		/* Tag: Exclude the C/P bit */
		tag = c & ASN1_TAG_MASK;
		print_tag(c, depth);

		printf(" ");

		/* Length */
		len = asn1_get_length(fp);
		if (len != ASN1_INDEFINITE_LENGTH)
			printf("L = %d\n", len);
		else
			printf("L = INDEFINITE\n");

		if (tag == ASN1_TAG_EOC) {
			length = 0; /* Complete current level */
			continue; /* Back to the upper level */
		}

		if (ASN1_IS_CONSTRUCTED(c)) {
			parse_asn1(fp, depth + 1, len);
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
		case ASN1_TAG_CONTEXT_SPECIFIC_8:
			parse_asn1(fp, depth + 1, len);
			goto next;
		}

		/* Content */
		if ((verbose_level > VERBOSE_LEVEL_NONE) && len) {
			switch (tag) {
			case ASN1_TAG_BOOLEAN:
				printf("%s", getc(fp) ? "TRUE" : "FALSE");
				break;
			case ASN1_TAG_INTEGER:
				print_octet_string(fp, len);
				break;
			case ASN1_TAG_BIT_STRING:
				print_bit_string(fp, len);
				break;
			case ASN1_TAG_OCTET_STRING:
				print_octet_string(fp, len);
				break;
			case ASN1_TAG_NULL:
				break;
			case ASN1_TAG_OBJECT_IDENTIFIER:
				print_object_identifier(fp, len);
				break;
			case ASN1_TAG_UTF8_STRING:
				print_printable_string(fp, len);
				break;
			case ASN1_TAG_PRINTABLE_STRING:
				print_printable_string(fp, len);
				break;
			case ASN1_TAG_T61_STRING:
			case ASN1_TAG_VID_STRING:
			case ASN1_TAG_IA5_STRING:
				/* Temporary */
				print_printable_string(fp, len);
				break;
			case ASN1_TAG_UTC:
			case ASN1_TAG_GENERALIZED_TIME:
				char time_str[MAX_STRING_LENGTH];
				get_time_string(fp, len, time_str);
				if (tag == ASN1_TAG_UTC)
					print_utc_time(time_str);
				else
					print_generalized_time(time_str);
				break;
			default:
				print_octet_string(fp, len);
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

	return ret;
}

const char *tag_name[256] = {
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

int print_tag(int code, int depth)
{
	int tag = code & ASN1_TAG_MASK;
	int i;
	for (i = 0; i < depth; i++)
		printf("-");
	if (verbose_level == VERBOSE_LEVEL_DEBUG)
		printf("Tag: %02x ", code);
	printf("%s ", tag_name[tag]);

	return 1;
}

int asn1_get_oid(FILE *fp, int length, uint8_t oid_value[], uint32_t *oid_len)
{
	for (int i = 0; i < length; i++) {
		oid_value[i] = getc(fp);
	}
	*oid_len = length;

	return 1;
}

int print_object_identifier(FILE *fp, int length)
{
	uint8_t asn1_oid_value[128];
	uint32_t oid_len = 0;
	asn1_get_oid(fp, length, asn1_oid_value, &oid_len);

	uint32_t oid_value[128];
	decode_asn1_oid(asn1_oid_value, oid_len, oid_value, &oid_len);
	int oid_type = asn1_lookup_oid(oid_value, oid_len);

	print_oid(oid_value, oid_len);

	if (oid_type != OID_TYPE_UNKNOWN) {
		printf(" (");
		print_oid_desc(oid_type);
		printf(")");
	}

	return oid_type;
}

void print_octet_string(FILE *fp, int length)
{
	for (int i = 0; i < length; i++) {
		int c = getc(fp);
		printf("%02x ", c);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}
}

void print_bit_string(FILE *fp, int length)
{
	int unused_bits = getc(fp);
	printf("Unused bits: %d\n", unused_bits);
	print_octet_string(fp, length - 1);
}

void print_printable_string(FILE *fp, int length)
{
	char str[MAX_STRING_LENGTH];
	for (int i = 0; i < length; i++) {
		str[i] = getc(fp);
	}
	str[length] = '\0';
	printf("%s", str);
}

void get_time_string(FILE *fp, int length, char *time_str)
{
	for (int i = 0; i < length; i++) {
		time_str[i] = getc(fp);
	}
	time_str[length] = '\0';
}

void print_time(int day, int month, int year, int hour, int minute, int second)
{
	// Month names
	const char *months[] = {
		"January",   "February", "March",    "April",
		"May",	     "June",	 "July",     "August",
		"September", "October",	 "November", "December"
	};

	// Print the formatted date and time
	printf("%d%s %s %d, %02d:%02d:%02d UTC\n", day,
	       (day == 1 || day == 21 || day == 31) ? "st" :
	       (day == 2 || day == 22)		    ? "nd" :
	       (day == 3 || day == 23)		    ? "rd" :
						      "th",
	       months[month - 1], year, hour, minute, second);
}

/** print_utc_time - print the UTC time included in the input character string to
 *  the stdout as readable text
 * 
 * @utc_str: input string containing the UTC time 
 * 
 * */
void print_utc_time(char *utc_str)
{
	int year, month, day, hour, minute, second;

	// Extract the time components from the UTC string
	sscanf(utc_str, "%2d%2d%2d%2d%2d%2d", &year, &month, &day, &hour,
	       &minute, &second);

	// Assuming the year is in the 21st century (20xx)
	year += 2000;

	print_time(day, month, year, hour, minute, second);
}

void print_generalized_time(char *generalized_time)
{
	int year, month, day, hour, minute, second;

	// Extract the time components from the Generalized time string
	sscanf(generalized_time, "%4d%2d%2d%2d%2d%2d", &year, &month, &day,
	       &hour, &minute, &second);

	print_time(day, month, year, hour, minute, second);
}

# POSIX-compliant Makefile
.POSIX:
# Reset suffixes
.SUFFIXES:

SHELL = /bin/sh

CC = cc

# Default CFLAGS (Release build)
# Note: -Wall and -Wextra are common but technically not POSIX; 
# however, most compilers (gcc, clang, suncc) support them.
# CFLAGS = -O2 -DNDEBUG -std=c99
CFLAGS = -Wall -Wextra -O2 -DNDEBUG -std=c99
CFLAGS_DBG = -g -O0 -DDEBUG -std=c99
LDFLAGS = -lm

INCLUDE_DIR = ../include

OBJS =	myrsa_math.o \
	big_number.o \
	myrsa.o \
	oid_database.o \
	oid.o \
	asn1.o \
	x509.o \
	mySHA.o \
	pem_der.o \
	mycrc.o \
	cms.o

TEST_MYRSA_MATH = test_myrsa_math
TEST_BIG_NUMBER = test_big_number
TEST_MYRSA = test_myrsa
TEST_ASN1 = test_asn1
TEST_MYSHA = test_mySHA

TEST_OID = test_oid

TEST_PEM_DER = test_pem_der

TEST_MYCRC = test_mycrc

TEST_PROGRAMS = $(TEST_MYRSA_MATH) \
	$(TEST_BIG_NUMBER) \
	$(TEST_MYRSA) \
	$(TEST_ASN1) \
	$(TEST_MYSHA) \
	$(TEST_OID) \
	$(TEST_PEM_DER) \
	$(TEST_MYCRC)

all: 	$(OBJS) \
	$(TEST_PROGRAMS)

# POSIX Standard Inference Rule for building common object files
.SUFFIXES: .c .o
.c.o:
	$(CC) $(CFLAGS) -c -I$(INCLUDE_DIR) $< -o $@
	@echo "Object file $@ created"

pem_der.o: $(INCLUDE_DIR)/pem_der.h
mycrc.o: $(INCLUDE_DIR)/mycrc.h
big_number.o: $(INCLUDE_DIR)/big_number.h
myrsa_math.o: $(INCLUDE_DIR)/myrsa_math.h
myrsa.o: $(INCLUDE_DIR)/myrsa.h $(INCLUDE_DIR)/myrsa_math.h $(INCLUDE_DIR)/big_number.h
oid.o: $(INCLUDE_DIR)/oid.h
oid_database.o: $(INCLUDE_DIR)/oid.h
asn1.o: $(INCLUDE_DIR)/asn1.h $(INCLUDE_DIR)/memfp.h $(INCLUDE_DIR)/oid.h
x509.o: $(INCLUDE_DIR)/x509.h $(INCLUDE_DIR)/asn1.h $(INCLUDE_DIR)/big_number.h $(INCLUDE_DIR)/oid.h $(INCLUDE_DIR)/memfp.h
mySHA.o: $(INCLUDE_DIR)/mySHA.h
pem_der.o: $(INCLUDE_DIR)/pem_der.h
cms.o: $(INCLUDE_DIR)/cms.h $(INCLUDE_DIR)/memfp.h $(INCLUDE_DIR)/asn1.h $(INCLUDE_DIR)/oid.h

$(TEST_MYRSA_MATH): $(TEST_MYRSA_MATH).c myrsa_math.o $(INCLUDE_DIR)/myrsa_math.h
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) $(TEST_MYRSA_MATH).c myrsa_math.o -o $(TEST_MYRSA_MATH) $(LDFLAGS)

$(TEST_BIG_NUMBER): $(TEST_BIG_NUMBER).c big_number.o $(INCLUDE_DIR)/big_number.h
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) $(TEST_BIG_NUMBER).c big_number.o -o $(TEST_BIG_NUMBER) $(LDFLAGS)

$(TEST_MYRSA): $(TEST_MYRSA).c $(OBJS) $(INCLUDE_DIR)/myrsa.h
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) $(TEST_MYRSA).c $(OBJS) -o $(TEST_MYRSA) $(LDFLAGS)

$(TEST_ASN1): $(TEST_ASN1).c $(OBJS) $(INCLUDE_DIR)/asn1.h $(INCLUDE_DIR)/memfp.h $(INCLUDE_DIR)/oid.h asn1.o
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) $(TEST_ASN1).c $(OBJS) -o $(TEST_ASN1) $(LDFLAGS)

$(TEST_OID): test_oid.c $(OBJS) $(INCLUDE_DIR)/oid.h
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -o $(TEST_OID) test_oid.c $(OBJS)

$(TEST_MYSHA): test_mySHA.c mySHA.o $(INCLUDE_DIR)/mySHA.h
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -o $(TEST_MYSHA) test_mySHA.c mySHA.o $(LDFLAGS)

$(TEST_PEM_DER): test_pem_der.c pem_der.o $(INCLUDE_DIR)/pem_der.h
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -o $(TEST_PEM_DER) test_pem_der.c pem_der.o $(LDFLAGS)

$(TEST_MYCRC): test_mycrc.c mycrc.o $(INCLUDE_DIR)/mycrc.h
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -o $(TEST_MYCRC) test_mycrc.c mycrc.o $(LDFLAGS)

# POSIX doesn't support target-specific variables like 'debug: CFLAGS += ...'
# Instead, we pass variables via the command line or use a separate build step
debug:
	$(MAKE) CFLAGS="$(CFLAGS_DBG)" clean all

test: $(TEST_PROGRAMS)
	@for test_prog in $(TEST_PROGRAMS); do \
		./$$test_prog; \
	done

clean:
	rm -f *.o \
	$(TEST_MYRSA_MATH) \
	$(TEST_BIG_NUMBER) \
	$(TEST_MYRSA) \
	$(TEST_ASN1) \
	$(TEST_MYSHA) \
	$(TEST_OID) \
	$(TEST_PEM_DER) \
	$(TEST_MYCRC)

.PHONY: all test clean debug

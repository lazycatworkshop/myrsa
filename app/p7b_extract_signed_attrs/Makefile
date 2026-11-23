# POSIX-compliant Makefile
.POSIX:
SHELL = /bin/sh

CC = cc
TARGET = p7b_extract_signed_attrs

# Default CFLAGS (Release build)
# Note: -Wall and -Wextra are common but technically not POSIX; 
# however, most compilers (gcc, clang, suncc) support them.
# CFLAGS = -O2 -DNDEBUG -std=c99
CFLAGS = -Wall -Wextra -pedantic -O2 -DNDEBUG -std=c99
CFLAGS_DBG = -g -O0 -DDEBUG -std=c99

INCLUDE_DIR = ../../include
COMMON_DIR = ../../common

HEADERS =	$(INCLUDE_DIR)/asn1.h \
		$(INCLUDE_DIR)/oid.h \
		$(INCLUDE_DIR)/cms.h \
		$(INCLUDE_DIR)/x509.h

COMMON_OBJS = 	$(COMMON_DIR)/oid.o \
		$(COMMON_DIR)/oid_database.o \
		$(COMMON_DIR)/big_number.o \
		$(COMMON_DIR)/asn1.o \
		$(COMMON_DIR)/x509.o \
		$(COMMON_DIR)/cms.o

all: $(TARGET)

$(TARGET): $(TARGET).c $(COMMON_OBJS) $(HEADERS)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) $(TARGET).c $(COMMON_OBJS) -o $(TARGET) $(LDFLAGS)

# BSD make does not work on cross-directory dependency well
# Build inside the common directory
$(COMMON_DIR)/oid.o:
	$(MAKE) -C $(COMMON_DIR) oid.o
$(COMMON_DIR)/oid_database.o:
	$(MAKE) -C $(COMMON_DIR) oid_database.o
$(COMMON_DIR)/big_number.o:
	$(MAKE) -C $(COMMON_DIR) big_number.o
$(COMMON_DIR)/asn1.o:
	$(MAKE) -C $(COMMON_DIR) asn1.o
$(COMMON_DIR)/x509.o:
	$(MAKE) -C $(COMMON_DIR) x509.o
$(COMMON_DIR)/cms.o:
	$(MAKE) -C $(COMMON_DIR) cms.o

# POSIX doesn't support target-specific variables like 'debug: CFLAGS += ...'
# Instead, we pass variables via the command line or use a separate build step
debug:
	$(MAKE) CFLAGS="$(CFLAGS_DBG)" clean all

test: $(TARGET)
	@sh ./test.sh

clean: # Local only
	rm -f *.o $(TARGET)

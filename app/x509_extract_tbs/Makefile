# POSIX-compliant Makefile
.POSIX:
SHELL = /bin/sh

CC = cc
TARGET = x509_extract_tbs

# Default CFLAGS (Release build)
# CFLAGS = -O2 -DNDEBUG -std=c99
CFLAGS = -Wall -Wextra -O2 -DNDEBUG -std=c99
CFLAGS_DBG = -g -O0 -DDEBUG -std=c99

INCLUDE_DIR = ../../include
COMMON_DIR = ../../common

COMMON_OBJS = 	$(COMMON_DIR)/oid.o \
		$(COMMON_DIR)/oid_database.o \
		$(COMMON_DIR)/big_number.o \
		$(COMMON_DIR)/asn1.o \
		$(COMMON_DIR)/x509.o

all: $(TARGET)

$(TARGET): $(TARGET).c $(COMMON_OBJS)
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

debug:
	$(MAKE) CFLAGS="$(CFLAGS_DBG)" clean all

test: $(TARGET)
	@sh ./test.sh

clean:
	rm -f *.o $(TARGET)

.PHONY: all test clean debug

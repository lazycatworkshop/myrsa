# POSIX-compliant Makefile
.POSIX:
SHELL = /bin/sh

CC = cc
TARGET = asn1parser

# Default CFLAGS (Release build)
# Note: -Wall and -Wextra are common but technically not POSIX; 
# however, most compilers (gcc, clang, suncc) support them.
# CFLAGS = -O2 -DNDEBUG -std=c99
CFLAGS = -Wall -Wextra -O2 -DNDEBUG -std=c99
CFLAGS_DBG = -g -O0 -DDEBUG -std=c99

INCLUDE_DIR = ../../include
COMMON_DIR = ../../common

COMMON_OBJS = 	$(COMMON_DIR)/asn1.o \
		$(COMMON_DIR)/oid.o \
		$(COMMON_DIR)/oid_database.o


all: $(TARGET)

$(TARGET): $(TARGET).c $(INCLUDE_DIR)/memfp.h $(COMMON_OBJS)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) $(TARGET).c $(COMMON_OBJS) -o $(TARGET) -lm

$(COMMON_DIR)/asn1.o:
	$(MAKE) -C $(COMMON_DIR) asn1.o
$(COMMON_DIR)/oid.o:
	$(MAKE) -C $(COMMON_DIR) oid.o

$(COMMON_DIR)/oid_database.o:
	$(MAKE) -C $(COMMON_DIR) oid_database.o

# POSIX doesn't support target-specific variables like 'debug: CFLAGS += ...'
# Instead, we pass variables via the command line or use a separate build step
debug:
	$(MAKE) CFLAGS="$(CFLAGS_DBG)" clean all

test: $(TARGET)
	@./test.sh

clean:
	rm -f *.o $(TARGET)

.PHONY: all test clean debug

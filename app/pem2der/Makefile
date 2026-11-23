# POSIX-compliant Makefile
.POSIX:
SHELL = /bin/sh

CC = cc
TARGET = pem2der

# Default CFLAGS (Release build)
# Note: -Wall and -Wextra are common but technically not POSIX; 
# however, most compilers (gcc, clang, suncc) support them.
# CFLAGS = -O2 -DNDEBUG -std=c99
CFLAGS = -Wall -Wextra -O2 -DNDEBUG -std=c99
CFLAGS_DBG = -g -O0 -DDEBUG -std=c99

INCLUDE_DIR = ../../include
COMMON_DIR = ../../common

COMMON_OBJS = 	$(COMMON_DIR)/pem_der.o

all: $(TARGET)

$(TARGET): $(TARGET).c $(COMMON_OBJS) $(INCLUDE_DIR)/pem_der.h
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) $(TARGET).c $(COMMON_OBJS) -o $(TARGET)

$(COMMON_DIR)/pem_der.o:
	$(MAKE) -C $(COMMON_DIR) pem_der.o

# POSIX doesn't support target-specific variables like 'debug: CFLAGS += ...'
# Instead, we pass variables via the command line or use a separate build step
debug:
	$(MAKE) CFLAGS="$(CFLAGS_DBG)" clean all

test: $(TARGET)
	@sh ./test.sh

clean:
	rm -f *.o $(TARGET)

.PHONY: all test clean debug

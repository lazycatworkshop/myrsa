# POSIX-compliant Makefile
.POSIX:
SHELL = /bin/sh

CC = cc
TARGET = demo_rsa_trapdoor

# Default CFLAGS (Release build)
# Note: -Wall and -Wextra are common but technically not POSIX; 
# however, most compilers (gcc, clang, suncc) support them.
# CFLAGS = -O2 -DNDEBUG -std=c99
CFLAGS = -Wall -Wextra -O2 -DNDEBUG -std=c99
CFLAGS_DBG = -g -O0 -DDEBUG -std=c99

all: $(TARGET)

$(TARGET): $(TARGET).o
	$(CC) $(CFLAGS) $(TARGET).o -o $(TARGET) -lm

# Keep the object file for objdump
$(TARGET).o: $(TARGET).c
	$(CC) $(CFLAGS) -c $(TARGET).c

# POSIX doesn't support target-specific variables like 'debug: CFLAGS += ...'
# Instead, we pass variables via the command line or use a separate build step
debug:
	$(MAKE) CFLAGS="$(CFLAGS_DBG)" clean all

test: $(TARGET)
	@./test.sh

clean:
	rm -f *.o $(TARGET)

.PHONY: all test clean

# Makefile

CC = gcc
CFLAGS = -Wall -Wextra -std=c89

# Debug build
ifeq ($(BUILD_TYPE), debug)
    CFLAGS = $(CFLAGS_common) -g -DDEBUG
else
# Release build
    CFLAGS = $(CFLAGS_common) -O2
endif

all: demo_rsa_keys test_myrsa test_myrsa_math

demo_rsa_keys: demo_rsa_keys.o myrsa_math.o myrsa.o
	$(CC) $(CFLAGS) $^ -o $@

demo_rsa_keys.o: demo_rsa_keys.c myrsa_math.h myrsa.h
	$(CC) $(CFLAGS) -c demo_rsa_keys.c -o demo_rsa_keys.o

myrsa_math.o: myrsa_math.c myrsa_math.h
	$(CC) $(CFLAGS) -c myrsa_math.c -o myrsa_math.o

myrsa.o: myrsa.c myrsa_math.h myrsa.h
	$(CC) $(CFLAGS) -c myrsa.c -o myrsa.o

test_myrsa_math: test_myrsa_math.o myrsa_math.o
	$(CC) $(CFLAGS) $^ -o $@

test_myrsa: test_myrsa.o myrsa_math.o myrsa.o
	$(CC) $(CFLAGS) $^ -o $@

test_myrsa_math.o: test_myrsa_math.c myrsa_math.h
	$(CC) $(CFLAGS) -c test_myrsa_math.c -o test_myrsa_math.o

test_myrsa.o: test_myrsa.c myrsa_math.h myrsa.h
	$(CC) $(CFLAGS) -c test_myrsa.c -o test_myrsa.o

.PHONY: clean

clean:
	rm -f demo_rsa_keys test_myrsa test_myrsa_math *.o

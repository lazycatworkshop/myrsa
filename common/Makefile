
CC = gcc
INC_DIR = ../include
CFLAGS = -Wall -I${INC_DIR} -MMD -MP -std=c99
OBJS = big_number.o \
	   myrsa.o \
	   myrsa_math.o \
	   mySHA.o \
	   oid.o

DEPS = big_number.d \
	   myrsa.d \
	   myrsa_math.d \
	   mySHA.d \
	   oid.d

ifdef DEBUG
CFLAGS += -g
else
CFLAGS += -O2 -DNDEBUG
endif

all: $(OBJS)

-include $(DEPS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o *.d
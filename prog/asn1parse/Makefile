CC = gcc
INC_DIR = ../../include
COMMON_DIR = ../../common
BIN_DIR = ../../bin
CFLAGS = -Wall -I${INC_DIR} -MMD -MP -std=c99
OBJS = asn1parse.o
COMMON_OBJS = ${COMMON_DIR}/oid.o
DEPS = asn1parse.d

ifdef DEBUG
CFLAGS += -g -DDEBUG
else
CFLAGS += -O2 -DNDEBUG
endif

all: bin asn1parse

bin:
	mkdir -p $(BIN_DIR)

asn1parse: $(OBJS) $(COMMON_OBJS)
	$(CC) -o $@ $^
	ln -sf $(abspath $@) $(BIN_DIR)/$@

-include $(DEPS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f asn1parse *.o *.d
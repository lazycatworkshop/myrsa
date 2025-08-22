CC = gcc
INC_DIR = ../../include
COMMON_DIR = ../../common
BIN_DIR = ../../bin
CFLAGS = -Wall -I${INC_DIR} -MMD -MP -std=c99
EXEC = x509_text_public_key
OBJS = ${EXEC}.o
COMMON_OBJS = ${COMMON_DIR}/oid.o
DEPS = ${EXEC}.d

ifdef DEBUG
CFLAGS += -g -DDEBUG
else
CFLAGS += -O2 -DNDEBUG
endif

all: bin ${EXEC}

bin:
	mkdir -p $(BIN_DIR)

${EXEC}: $(OBJS) $(COMMON_OBJS)
	$(CC) -o $@ $^
	ln -sf $(abspath $@) $(BIN_DIR)/$@

-include $(DEPS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f ${EXEC} *.o *.d
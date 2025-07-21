CC = gcc
INC_DIR = ../../include
COMMON_DIR = ../../common
TEST_DIR = ../../test
CFLAGS = -Wall -I${INC_DIR} -MMD -MP -std=c99
EXEC = test_myrsa
OBJS = ${EXEC}.o
COMMON_OBJS = $(COMMON_DIR)/big_number.o \
			  $(COMMON_DIR)/myrsa.o \
			  $(COMMON_DIR)/myrsa_math.o \
			  $(COMMON_DIR)/mySHA.o \



DEPS = ${EXEC}.d big_number.d myrsa.d myrsa_math.d mySHA.d

ifdef DEBUG
CFLAGS += -g
else
CFLAGS += -O2 # Do not define NDEBUG to keep assertions in place
endif

all: test ${EXEC}

test:
	mkdir -p $(TEST_DIR)

${EXEC}: $(OBJS) $(COMMON_OBJS)
	$(CC) -o $@ $^
	ln -sf $(abspath $@) $(TEST_DIR)/$@

-include $(DEPS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f ${EXEC} *.o *.d
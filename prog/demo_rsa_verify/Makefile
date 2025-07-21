CC = gcc
INC_DIR = ../../include
COMMON_DIR = ../../common
BIN_DIR = ../../bin
CFLAGS = -Wall -I${INC_DIR} -MMD -MP -std=c99
OBJS = demo_rsa_verify.o
COMMON_OBJS = $(COMMON_DIR)/big_number.o \
			  $(COMMON_DIR)/myrsa.o \
			  $(COMMON_DIR)/myrsa_math.o \
			  $(COMMON_DIR)/mycrc.o
DEPS = demo_rsa_verify.d myrsa.d myrsa_math.d big_number.d mycrc.d

ifdef DEBUG
CFLAGS += -g
else
CFLAGS += -O2 -DNDEBUG
endif

all: bin demo_rsa_verify

bin: 
	mkdir -p $(BIN_DIR)

demo_rsa_verify: $(OBJS) $(COMMON_OBJS)
	$(CC) -o $@ $^
	ln -sf $(abspath $@) $(BIN_DIR)/$@

-include $(DEPS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f demo_rsa_verify *.o *.d
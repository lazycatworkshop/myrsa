CC = gcc
INC_DIR = ../../include
COMMON_DIR = ../../common
BIN_DIR = ../../bin
CFLAGS = -Wall -I${INC_DIR} -MMD -MP -std=c99
OBJS = demo_rsa_keys.o
COMMON_OBJS = $(COMMON_DIR)/big_number.o \
			  $(COMMON_DIR)/myrsa.o \
			  $(COMMON_DIR)/myrsa_math.o
DEPS = demo_rsa_keys.d myrsa.d myrsa_math.d big_number.d

ifdef DEBUG
CFLAGS += -g
else
CFLAGS += -O2 -DNDEBUG
endif

all: bin demo_rsa_keys

bin: 
	mkdir -p $(BIN_DIR)

demo_rsa_keys: $(OBJS) $(COMMON_OBJS)
	$(CC) -o $@ $^
	ln -sf $(abspath $@) $(BIN_DIR)/$@

-include $(DEPS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f demo_rsa_keys *.o *.d
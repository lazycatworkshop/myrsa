CC = gcc
INC_DIR = ../../include
COMMON_DIR = ../../common
BIN_DIR = ../../bin
CFLAGS = -Wall -I${INC_DIR} -MMD -MP -std=c99
OBJS = myrsa_trapdoor.o
COMMON_OBJS = $(COMMON_DIR)/big_number.o \
			  $(COMMON_DIR)/myrsa.o \
			  $(COMMON_DIR)/myrsa_math.o

DEPS = myrsa_trapdoor.d myrsa.d big_number.d myrsa_math.d

ifdef DEBUG
CFLAGS += -g
else
CFLAGS += -O2 -DNDEBUG
endif

all: bin myrsa_trapdoor

bin: 
	mkdir -p $(BIN_DIR)

myrsa_trapdoor: $(OBJS) $(COMMON_OBJS)
	$(CC) -o $@ $^
	ln -sf $(abspath $@) $(BIN_DIR)/$@

-include $(DEPS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f myrsa_trapdoor *.o *.d
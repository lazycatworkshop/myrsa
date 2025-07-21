CC = gcc
INC_DIR = .
BIN_DIR = ../../bin
CFLAGS = -Wall -I${INC_DIR} -MMD -MP -std=c99
OBJS = demo_rsa_trapdoor.o
COMMON_OBJS =
DEPS = demo_rsa_trapdoor.d

ifdef DEBUG
CFLAGS += -g
else
CFLAGS += -O2 -DNDEBUG
endif

all: bin demo_rsa_trapdoor

bin:
	mkdir -p $(BIN_DIR)

demo_rsa_trapdoor: $(OBJS) $(COMMON_OBJS)
	$(CC) -o $@ $^
	ln -sf $(abspath $@) $(BIN_DIR)/$@

-include $(DEPS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f demo_rsa_trapdoor *.o *.d
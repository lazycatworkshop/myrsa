CC = gcc
INC_DIR = .
BIN_DIR = ../../bin
CFLAGS = -Wall -I${INC_DIR} -MMD -MP -std=c99
OBJS = csr_text.o
COMMON_OBJS =
DEPS = csr_text.d

ifdef DEBUG
CFLAGS += -g
else
CFLAGS += -O2 -DNDEBUG
endif

all: bin csr_text

bin: 
	mkdir -p $(BIN_DIR)

csr_text: $(OBJS) $(COMMON_OBJS)
	$(CC) -o $@ $^
	ln -sf $(abspath $@) $(BIN_DIR)/$@

-include $(DEPS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f csr_text *.o *.d
CC=gcc
CFLAGS=-Wall -Iinclude -std=c99
# Conditional debug flags based on the DEBUG variable
ifdef DEBUG
CFLAGS += -g -O0 -DDEBUG
else
CFLAGS += -O2
endif

SRC_DIR=src
OBJ_DIR=obj
BIN_DIR=bin
TEST_SRC_DIR=test
TEST_BIN_DIR=test

INC_DIR=include
CCFLAG += -I$(INC_DIR)

# Define executables and their specific source files
EXECUTABLES=demo_rsa_keys myrsa_sign myrsa_verify
demo_rsa_keys_SOURCES=$(SRC_DIR)/demo_rsa_keys.c $(SRC_DIR)/myrsa.c  $(SRC_DIR)/myrsa_math.c
myrsa_sign_SOURCES=$(SRC_DIR)/myrsa_sign.c $(SRC_DIR)/myrsa.c $(SRC_DIR)/myrsa_math.c
myrsa_verify_SOURCES=$(SRC_DIR)/myrsa_verify.c $(SRC_DIR)/myrsa.c $(SRC_DIR)/myrsa_math.c

# Convert source files to object files for each executable
demo_rsa_keys_OBJECTS=$(demo_rsa_keys_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
myrsa_sign_OBJECTS=$(myrsa_sign_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
myrsa_verify_OBJECTS=$(myrsa_verify_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

TEST_BINARIES=test_myrsa test_myrsa_math
test_myrsa_SOURCES=$(SRC_DIR)/test_myrsa.c $(SRC_DIR)/myrsa.c $(SRC_DIR)/myrsa_math.c
test_myrsa_math_SOURCES=$(SRC_DIR)/test_myrsa_math.c $(SRC_DIR)/myrsa_math.c

# Convert source files to object files for each test binary
test_myrsa_OBJECTS=$(test_myrsa_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
test_myrsa_math_OBJECTS=$(test_myrsa_math_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# Targets for executables
all: $(OBJ_DIR) $(BIN_DIR) $(TEST_BIN_DIR) $(EXECUTABLES) $(TEST_BINARIES)

# Rule to create directories
$(OBJ_DIR) $(BIN_DIR) $(TEST_BIN_DIR):
	@mkdir -p $(OBJ_DIR) $(BIN_DIR) $(TEST_BIN_DIR)

demo_rsa_keys: $(demo_rsa_keys_OBJECTS)
	$(CC) $^ -o $(BIN_DIR)/$@

myrsa_sign: $(myrsa_sign_OBJECTS)
	$(CC) $^ -o $(BIN_DIR)/$@

myrsa_verify: $(myrsa_verify_OBJECTS)
	$(CC) $^ -o $(BIN_DIR)/$@

# Compile test sources into test binaries

test_myrsa: $(test_myrsa_OBJECTS)
	$(CC) $^ -o $(TEST_BIN_DIR)/$@

test_myrsa_math: $(test_myrsa_math_OBJECTS)
	$(CC) $^ -o $(TEST_BIN_DIR)/$@

# Test target
#.PHONY: test
#test: $(TEST_BINARIES)
#	@for test_bin in $(TEST_BINARIES); do \
#	echo Running $$test_bin; \
#	$(TEST_BIN_DIR)/$$test_bin; \
#	done

# Generic rule for compiling source files to object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean target
.PHONY: clean
clean:
	rm -rf $(OBJ_DIR)/* $(BIN_DIR)/* $(TEST_BIN_DIR)/*

clean_dir:
	rm -rf $(OBJ_DIR) $(BIN_DIR) $(TEST_BIN_DIR)

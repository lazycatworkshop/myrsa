CC=gcc
CFLAGS=-Wall -Iinclude -std=c99
# Conditional debug flags based on the DEBUG variable
ifdef DEBUG
CFLAGS += -g -O0
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
EXECUTABLES=demo_rsa_keys demo_rsa_sign demo_rsa_verify pem2der asn1parse rsa_text_public_key x509_text_public_key
demo_rsa_keys_SOURCES=$(SRC_DIR)/demo_rsa_keys.c $(SRC_DIR)/myrsa.c  $(SRC_DIR)/myrsa_math.c
demo_rsa_sign_SOURCES=$(SRC_DIR)/demo_rsa_sign.c $(SRC_DIR)/myrsa.c $(SRC_DIR)/myrsa_math.c $(SRC_DIR)/mycrc.c
demo_rsa_verify_SOURCES=$(SRC_DIR)/demo_rsa_verify.c $(SRC_DIR)/myrsa.c $(SRC_DIR)/myrsa_math.c $(SRC_DIR)/mycrc.c
pem2der_SOURCES=$(SRC_DIR)/pem2der.c
asn1parse_SOURCES=$(SRC_DIR)/asn1parse.c
rsa_text_public_key_SOURCES=$(SRC_DIR)/rsa_text_public_key.c

# Convert source files to object files for each executable
demo_rsa_keys_OBJECTS=$(demo_rsa_keys_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
demo_rsa_sign_OBJECTS=$(demo_rsa_sign_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
demo_rsa_verify_OBJECTS=$(demo_rsa_verify_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
pem2der_OBJECTS=$(pem2der_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
asn1parse_OBJECTS=$(asn1parse_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
rsa_text_public_key_OBJECTS=$(rsa_text_public_key_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

TEST_BINARIES=test_myrsa test_myrsa_math test_mycrc
test_myrsa_SOURCES=$(SRC_DIR)/test_myrsa.c $(SRC_DIR)/myrsa.c $(SRC_DIR)/myrsa_math.c
test_myrsa_math_SOURCES=$(SRC_DIR)/test_myrsa_math.c $(SRC_DIR)/myrsa_math.c
test_mycrc_SOURCES=$(SRC_DIR)/test_mycrc.c $(SRC_DIR)/mycrc.c

# Convert source files to object files for each test binary
test_myrsa_OBJECTS=$(test_myrsa_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
test_myrsa_math_OBJECTS=$(test_myrsa_math_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
test_mycrc_OBJECTS=$(test_mycrc_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# Targets for executables
all: $(OBJ_DIR) $(BIN_DIR) $(TEST_BIN_DIR) $(EXECUTABLES) $(TEST_BINARIES)

# Rule to create directories
$(OBJ_DIR) $(BIN_DIR) $(TEST_BIN_DIR):
	@mkdir -p $(OBJ_DIR) $(BIN_DIR) $(TEST_BIN_DIR)

demo_rsa_keys: $(demo_rsa_keys_OBJECTS)
	$(CC) $^ -o $(BIN_DIR)/$@

demo_rsa_sign: $(demo_rsa_sign_OBJECTS)
	$(CC) $^ -o $(BIN_DIR)/$@

demo_rsa_verify: $(demo_rsa_verify_OBJECTS)
	$(CC) $^ -o $(BIN_DIR)/$@

pem2der: $(pem2der_OBJECTS)
	$(CC) $^ -o $(BIN_DIR)/$@

asn1parse: $(asn1parse_OBJECTS)
	$(CC) $^ -o $(BIN_DIR)/$@

rsa_text_public_key: $(rsa_text_public_key_OBJECTS)
	$(CC) $^ -o $(BIN_DIR)/$@

x509_text_public_key: $(SRC_DIR)/x509_text_public_key.c
	$(CC) $(CFLAGS) $^ -o $(BIN_DIR)/$@

# Compile test sources into test binaries

test_myrsa: $(test_myrsa_OBJECTS)
	$(CC) $^ -o $(TEST_BIN_DIR)/$@

test_mycrc: $(test_mycrc_OBJECTS)
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

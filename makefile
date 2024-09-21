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
EXECUTABLES=demo_rsa_keys \
            demo_rsa_sign \
	    demo_rsa_verify \
	    demo_rsa_trapdoor \
	    pem2der asn1parse \
	    rsa_text_public_key \
	    x509_text_public_key \
	    x509_extract_tbs \
	    x509_extract_sig \
	    x509_extract_pubkey \
	    der2pem myrsa_sha256 \
	    myrsa_trapdoor \
	    myrsa_sha1
	    
demo_rsa_keys_SOURCES=$(SRC_DIR)/demo_rsa_keys.c $(SRC_DIR)/myrsa.c  $(SRC_DIR)/myrsa_math.c $(SRC_DIR)/big_number.c
demo_rsa_sign_SOURCES=$(SRC_DIR)/demo_rsa_sign.c $(SRC_DIR)/myrsa.c $(SRC_DIR)/myrsa_math.c $(SRC_DIR)/mycrc.c $(SRC_DIR)/big_number.c
demo_rsa_verify_SOURCES=$(SRC_DIR)/demo_rsa_verify.c $(SRC_DIR)/myrsa.c $(SRC_DIR)/myrsa_math.c $(SRC_DIR)/mycrc.c $(SRC_DIR)/big_number.c
myrsa_trapdoor_SOURCES=$(SRC_DIR)/myrsa_trapdoor.c $(SRC_DIR)/myrsa.c $(SRC_DIR)/myrsa_math.c $(SRC_DIR)/big_number.c

# Convert source files to object files for each executable
demo_rsa_keys_OBJECTS=$(demo_rsa_keys_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
demo_rsa_sign_OBJECTS=$(demo_rsa_sign_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
demo_rsa_verify_OBJECTS=$(demo_rsa_verify_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
myrsa_trapdoor_OBJECTS=$(myrsa_trapdoor_SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

TEST_BINARIES=test_myrsa test_myrsa_math test_mycrc
test_myrsa_SOURCES=$(SRC_DIR)/test_myrsa.c $(SRC_DIR)/myrsa.c $(SRC_DIR)/myrsa_math.c $(SRC_DIR)/mySHA.c $(SRC_DIR)/big_number.c
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
	$(CC) $(CFLAGS) $^ -o $(BIN_DIR)/$@

demo_rsa_sign: $(demo_rsa_sign_OBJECTS)
	$(CC) $(CFLAGS) $^ -o $(BIN_DIR)/$@

demo_rsa_verify: $(demo_rsa_verify_OBJECTS)
	$(CC) $(CFLAGS) $^ -o $(BIN_DIR)/$@

demo_rsa_trapdoor: $(SRC_DIR)/demo_rsa_trapdoor.c
	$(CC) $(CFLAGS) $^ -o $(BIN_DIR)/$@

myrsa_trapdoor: $(myrsa_trapdoor_OBJECTS)
	$(CC) $(CFLAGS) $^ -o $(BIN_DIR)/$@

pem2der: $(SRC_DIR)/pem2der.c
	$(CC) $(CFLAGS) $^ -o $(BIN_DIR)/$@

asn1parse: $(SRC_DIR)/asn1parse.c
	$(CC) $(CFLAGS) $^ -o $(BIN_DIR)/$@

rsa_text_public_key: $(SRC_DIR)/rsa_text_public_key.c
	$(CC) $(CFLAGS) $^ -o $(BIN_DIR)/$@

x509_text_public_key: $(SRC_DIR)/x509_text_public_key.c
	$(CC) $(CFLAGS) $^ -o $(BIN_DIR)/$@

x509_extract_tbs: $(SRC_DIR)/x509_extract_tbs.c
	$(CC) $(CFLAGS) $^ -o $(BIN_DIR)/$@

x509_extract_sig: $(SRC_DIR)/x509_extract_sig.c
	$(CC) $(CFLAGS) $^ -o $(BIN_DIR)/$@

x509_extract_pubkey: $(SRC_DIR)/x509_extract_pubkey.c
	$(CC) $(CFLAGS) $^ -o $(BIN_DIR)/$@

der2pem: $(SRC_DIR)/der2pem.c
	$(CC) $(CFLAGS) $^ -o $(BIN_DIR)/$@

myrsa_sha256: $(SRC_DIR)/myrsa_sha256.c $(SRC_DIR)/mySHA.c
	$(CC) $(CFLAGS) $^ -o $(BIN_DIR)/$@

myrsa_sha1: $(SRC_DIR)/myrsa_sha1.c $(SRC_DIR)/mySHA.c
	$(CC) $(CFLAGS) $^ -o $(BIN_DIR)/$@

# Compile test sources into test binaries

test_myrsa: $(test_myrsa_OBJECTS)
	$(CC) $(CFLAGS) $^ -o $(TEST_BIN_DIR)/$@

test_mycrc: $(test_mycrc_OBJECTS)
	$(CC) $(CFLAGS) $^ -o $(TEST_BIN_DIR)/$@

test_myrsa_math: $(test_myrsa_math_OBJECTS)
	$(CC) $(CFLAGS) $^ -o $(TEST_BIN_DIR)/$@

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

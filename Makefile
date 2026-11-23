# POSIX-compliant Makefile
.POSIX:
SHELL = /bin/sh

# List of subdirectories to build
SUBDIRS =	common \
		app/asn1parser \
		app/demo_rsa_keys \
		app/demo_rsa_trapdoor \
		app/get_cert \
		app/x509_text_public_key \
		app/x509_extract_tbs \
		app/x509_extract_sig \
		app/x509_extract_pubkey \
		app/myrsa_trapdoor \
		app/myrsa_sha256 \
		app/pem2der \
		app/p7b_text \
		app/p7b_extract_cert \
		app/p7b_extract_sig \
		app/p7b_extract_signed_attrs \
		app/demo_rsa_sign \
		app/csr_text
		
# Automatically find subdirectories containing a Makefile
# SUBDIRS = $(shell find . -mindepth 3 -maxdepth 4 -name "Makefile" -exec dirname {} \; | sed 's|^\./||')

# Default target: build all subprojects
all: $(SUBDIRS)

# Recursive call to each subdirectory
$(SUBDIRS):
	$(MAKE) -C $@

# Test all subprojects
# Check for missing entries in SUBDIRS first
test:
	@missing=0; \
	for mk in common/Makefile app/*/Makefile; do \
		dir=$$(dirname "$$mk"); \
		case " $(SUBDIRS) " in \
			*" $$dir "*) ;; \
			*) echo "Error: $$dir is not listed in SUBDIRS"; missing=1 ;; \
		esac; \
	done; \
	[ $$missing -eq 0 ] || exit 1
	@for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir test; \
	done

# Clean all subprojects
clean:
	@for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir clean; \
	done

.PHONY: all test clean $(SUBDIRS)

# Top-level
PROG_DIR = prog
SUBDIRS := common \
	   ${PROG_DIR}/asn1parse \
	   ${PROG_DIR}/csr_text \
	   ${PROG_DIR}/demo_rsa_keys \
	   ${PROG_DIR}/demo_rsa_sign \
	   ${PROG_DIR}/demo_rsa_trapdoor \
	   ${PROG_DIR}/demo_rsa_verify \
	   ${PROG_DIR}/der2pem \
	   ${PROG_DIR}/myrsa_trapdoor \
	   ${PROG_DIR}/myrsa_sha1 \
	   ${PROG_DIR}/myrsa_sha256 \
	   ${PROG_DIR}/p7b_extract_cert \
	   ${PROG_DIR}/p7b_extract_sig \
	   ${PROG_DIR}/p7b_extract_signed_attrs \
	   ${PROG_DIR}/p7b_text \
	   ${PROG_DIR}/pem2der \
	   ${PROG_DIR}/rsa_text_public_key \
	   ${PROG_DIR}/test_mycrc \
	   ${PROG_DIR}/test_myrsa_math \
	   ${PROG_DIR}/test_myrsa \
	   ${PROG_DIR}/x509_extract_pubkey \
	   ${PROG_DIR}/x509_extract_sig \
	   ${PROG_DIR}/x509_extract_tbs \
	   ${PROG_DIR}/x509_text_public_key \
	   ${PROG_DIR}/test_oid \



.PHONY: all clean $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

clean:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir clean; \
	done
	rm -r bin
	rm -r test
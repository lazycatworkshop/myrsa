#!/bin/sh

BINARY="./p7b_extract_signed_attrs"
TMPDIR=${TMPDIR:-/tmp}
WORK_BASE=$TMPDIR/p7b_extract_signed_attrs-test.$$
WORK_DIR=$WORK_BASE
suffix=0

while ! mkdir "$WORK_DIR" 2>/dev/null; do
	suffix=$((suffix + 1))
	if [ "$suffix" -ge 100 ]; then
		echo "Error: Cannot create temporary directory" >&2
		exit 1
	fi
	WORK_DIR=$WORK_BASE.$suffix
done

passed=0
failed=0

cleanup() {
	rm -rf "$WORK_DIR"
}
trap cleanup 0
trap 'exit 1' 1 2 3 15

if [ ! -x "$BINARY" ]; then
	echo "Error: Binary '$BINARY' not found or not executable. Compile it first." >&2
	exit 1
fi

pass() {
	echo "[PASS] $1"
	passed=$((passed + 1))
}

fail() {
	echo "[FAIL] $1"
	if [ -n "$2" ]; then
		echo "       $2"
	fi
	failed=$((failed + 1))
}

# run_test <name> <expected exit> <expected output substring> [args...]
run_test() {
	name=$1
	expected_exit=$2
	expected_output=$3
	shift 3

	output=$("$BINARY" "$@" 2>&1)
	status=$?
	if [ "$status" -eq "$expected_exit" ] && {
		[ -z "$expected_output" ] ||
		echo "$output" | grep -F "$expected_output" >/dev/null 2>&1
	}; then
		pass "$name"
	else
		fail "$name" "expected exit $expected_exit and output containing '$expected_output'; got exit $status: $output"
	fi
}

: >"$WORK_DIR/empty.p7b"
printf '%s\n' '-----BEGIN PKCS7-----' 'AAAA' '-----END PKCS7-----' \
	>"$WORK_DIR/pem.p7b"
printf '\060\000' >"$WORK_DIR/malformed.der"

echo "Running p7b_extract_signed_attrs tests..."
run_test "Missing arguments" 1 "Usage:"
run_test "Missing input option" 1 "Usage:" -o "$WORK_DIR/out.bin"
run_test "Missing output option" 1 "Usage:" -i "$WORK_DIR/empty.p7b"
run_test "Missing option argument" 1 "Usage:" -i
run_test "Unknown option" 1 "Usage:" -x foo
run_test "Nonexistent input file" 1 "Cannot open file" \
	-i "$WORK_DIR/nonexistent.p7b" -o "$WORK_DIR/out.bin"
run_test "Empty input file" 1 "File is empty" \
	-i "$WORK_DIR/empty.p7b" -o "$WORK_DIR/empty-out.bin"
run_test "PEM input rejected" 1 "Expected top level SEQUENCE" \
	-i "$WORK_DIR/pem.p7b" -o "$WORK_DIR/pem-out.bin"
run_test "Malformed DER rejected" 1 "Failed to load contentType" \
	-i "$WORK_DIR/malformed.der" -o "$WORK_DIR/malformed-out.bin"

if ! command -v openssl >/dev/null 2>&1; then
	echo "Skipping valid PKCS#7 signedAttrs test: openssl not found"
else
	key="$WORK_DIR/key.pem"
	cert_pem="$WORK_DIR/cert.pem"
	data="$WORK_DIR/data.txt"
	p7b_der="$WORK_DIR/signed.der"
	attrs_output="$WORK_DIR/extracted.der"
	attrs_expected="$WORK_DIR/expected.der"
	noattrs_der="$WORK_DIR/noattrs.der"

	echo "p7b signedAttrs test" >"$data"
	if openssl req -x509 -newkey rsa:2048 -nodes -sha256 \
		-keyout "$key" -subj "/CN=p7b-test.example" -days 2 \
		-out "$cert_pem" >/dev/null 2>&1 &&
		openssl smime -sign -binary -in "$data" -signer "$cert_pem" \
			-inkey "$key" -outform DER -out "$p7b_der" \
			>/dev/null 2>&1 &&
		[ -s "$p7b_der" ]; then
		output=$("$BINARY" -i "$p7b_der" -o "$attrs_output" 2>&1)
		status=$?
		if [ "$status" -eq 0 ]; then
			pass "DER PKCS#7 signed data accepted"
		else
			fail "DER PKCS#7 signed data accepted" "exit $status: $output"
		fi

		# signedAttrs is the [0] IMPLICIT item at depth 5 in the SignerInfo
		line=$(openssl asn1parse -inform DER -in "$p7b_der" 2>/dev/null |
			grep 'd=5 .*cons: cont \[ 0 \]' | tail -n 1)
		offset=${line%%:*}
		offset=${offset##* }
		hl=${line#*hl=}
		hl=${hl%% l=*}
		hl=$(echo "$hl" | tr -d ' ')
		len=${line#*hl=*l=}
		len=${len%%c*}
		len=$(echo "$len" | tr -d ' ')
		if [ -n "$offset" ] && [ -n "$hl" ] && [ -n "$len" ] &&
			dd if="$p7b_der" of="$attrs_expected" bs=1 \
				skip=$((offset + hl)) count="$len" \
				>/dev/null 2>&1 &&
			[ "$status" -eq 0 ] &&
			[ "$(od -An -tx1 -N1 "$attrs_output" | tr -d ' ')" = "31" ] &&
			tail -c "$len" "$attrs_output" | cmp -s - "$attrs_expected"; then
			pass "Extracted signedAttrs matches source, tagged as SET"
		else
			fail "Extracted signedAttrs matches source, tagged as SET"
		fi

		# Parsable as a SET OF Attribute by openssl
		if openssl asn1parse -inform DER -in "$attrs_output" \
			>/dev/null 2>&1; then
			pass "Extracted signedAttrs is valid DER"
		else
			fail "Extracted signedAttrs is valid DER"
		fi
	else
		echo "Skipping valid PKCS#7 signedAttrs test: unable to create signed data"
	fi

	if openssl smime -sign -binary -noattr -in "$data" \
		-signer "$cert_pem" -inkey "$key" -outform DER \
		-out "$noattrs_der" >/dev/null 2>&1 &&
		[ -s "$noattrs_der" ]; then
		run_test "SignerInfo without signedAttrs rejected" 1 \
			"No signedAttrs" \
			-i "$noattrs_der" -o "$WORK_DIR/noattrs-out.bin"
	fi
fi

echo
echo "Test summary: $passed passed, $failed failed."
[ "$failed" -eq 0 ]

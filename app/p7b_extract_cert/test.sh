#!/bin/sh

BINARY="./p7b_extract_cert"
TMPDIR=${TMPDIR:-/tmp}
WORK_BASE=$TMPDIR/p7b_extract_cert-test.$$
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

echo "Running p7b_extract_cert tests..."
run_test "Missing arguments" 1 "Usage:"
run_test "Missing input option" 1 "Usage:" -o "$WORK_DIR/out.der"
run_test "Missing output option" 1 "Usage:" -i "$WORK_DIR/empty.p7b"
run_test "Missing option argument" 1 "Usage:" -i
run_test "Unknown option" 1 "Usage:" -x foo
run_test "Nonexistent input file" 1 "Cannot open file" \
	-i "$WORK_DIR/nonexistent.p7b" -o "$WORK_DIR/out.der"
run_test "Empty input file" 0 "File is empty" \
	-i "$WORK_DIR/empty.p7b" -o "$WORK_DIR/empty-out.der"
run_test "PEM input rejected" 1 "Expected top level SEQUENCE" \
	-i "$WORK_DIR/pem.p7b" -o "$WORK_DIR/pem-out.der"
run_test "Malformed DER rejected" 1 "Failed to load contentType" \
	-i "$WORK_DIR/malformed.der" -o "$WORK_DIR/malformed-out.der"

if ! command -v openssl >/dev/null 2>&1; then
	echo "Skipping valid PKCS#7 extraction test: openssl not found"
else
	key="$WORK_DIR/key.pem"
	cert_pem="$WORK_DIR/cert.pem"
	cert_der="$WORK_DIR/cert.der"
	p7b_der="$WORK_DIR/bundle.der"
	cert_output="$WORK_DIR/extracted.der"

	if openssl req -x509 -newkey rsa:2048 -nodes -sha256 \
		-keyout "$key" -subj "/CN=p7b-test.example" -days 2 \
		-out "$cert_pem" >/dev/null 2>&1 &&
		openssl x509 -in "$cert_pem" -outform DER -out "$cert_der" \
			>/dev/null 2>&1 &&
		openssl crl2pkcs7 -nocrl -certfile "$cert_pem" -outform DER \
			-out "$p7b_der" >/dev/null 2>&1 &&
		[ -s "$cert_der" ] && [ -s "$p7b_der" ]; then
		output=$("$BINARY" -i "$p7b_der" -o "$cert_output" 2>&1)
		status=$?
		if [ "$status" -eq 0 ]; then
			pass "DER PKCS#7 bundle accepted"
		else
			fail "DER PKCS#7 bundle accepted" "exit $status: $output"
		fi

		if [ "$status" -eq 0 ] && cmp -s "$cert_output" "$cert_der"; then
			pass "Extracted certificate matches source certificate"
		else
			fail "Extracted certificate matches source certificate"
		fi
	else
		echo "Skipping valid PKCS#7 extraction test: unable to create test certificate and bundle"
	fi
fi

echo
echo "Test summary: $passed passed, $failed failed."
[ "$failed" -eq 0 ]
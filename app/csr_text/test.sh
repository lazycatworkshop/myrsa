#!/bin/sh

BINARY="./csr_text"
TMPDIR=${TMPDIR:-/tmp}
WORK_DIR=$(mktemp -d "$TMPDIR/csr_text-test.XXXXXX") || exit 1

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
	[ -n "$2" ] && echo "       $2"
	failed=$((failed + 1))
}

# run_test <name> <expected exit> <expected output substring> [args...]
run_test() {
	name=$1
	expected_exit=$2
	expected_output=$3
	shift 3

	output=$($BINARY "$@" 2>&1)
	status=$?

	if [ "$status" -eq "$expected_exit" ] &&
		echo "$output" | grep -F -- "$expected_output" >/dev/null 2>&1; then
		pass "$name"
	else
		fail "$name" "expected exit $expected_exit and output containing '$expected_output'; got exit $status: $output"
	fi
}

: >"$WORK_DIR/empty.der"
printf '%s\n' '-----BEGIN CERTIFICATE REQUEST-----' 'AAAA' \
	'-----END CERTIFICATE REQUEST-----' >"$WORK_DIR/pem.csr"
	
echo "Running csr_text tests..."
run_test "Missing arguments" 1 "Usage:"
run_test "Unknown option" 1 "Usage:" -x foo
run_test "Missing option argument" 1 "Usage:" -f
run_test "Nonexistent file" 1 "Failed to open file" \
	-f "$WORK_DIR/nonexistent.der"
run_test "Empty file" 1 "File is empty" -f "$WORK_DIR/empty.der"
run_test "PEM file" 1 "File is in PEM format" -f "$WORK_DIR/pem.csr"

if command -v openssl >/dev/null 2>&1 &&
	openssl req -new -newkey rsa:2048 -nodes \
		-keyout "$WORK_DIR/key.pem" -outform DER \
		-out "$WORK_DIR/test.der" \
		-subj "/C=US/O=Example Org/CN=example.com" \
		>/dev/null 2>&1 && [ -s "$WORK_DIR/test.der" ]; then
	run_test "CSR header" 0 "Certificate Request:" -f "$WORK_DIR/test.der"
	run_test "CSR subject" 0 "CN=example.com" -f "$WORK_DIR/test.der"
	run_test "CSR public key" 0 "algorithm: rsaEncryption" \
		-f "$WORK_DIR/test.der"
	run_test "CSR signature algorithm" 0 "sha256WithRSAEncryption" \
		-f "$WORK_DIR/test.der"
else
	echo "[SKIP] Generated CSR tests: OpenSSL unavailable"
fi

echo "Test summary: $passed passed, $failed failed."

[ "$failed" -eq 0 ]

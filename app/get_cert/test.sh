#!/bin/sh

BINARY="./get_cert"
TMPDIR=${TMPDIR:-/tmp}
WORK_DIR=$(mktemp -d "$TMPDIR/get_cert-test.XXXXXX") || exit 1

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

run_test() {
	name=$1
	expected_exit=$2
	expected_output=$3
	shift 3

	output=$($BINARY "$@" 2>&1)
	status=$?

	if [ "$status" -eq "$expected_exit" ] &&
		echo "$output" | grep -F "$expected_output" >/dev/null 2>&1; then
		echo "[PASS] $name"
		passed=$((passed + 1))
	else
		echo "[FAIL] $name"
		echo "       expected exit $expected_exit and output containing: $expected_output"
		echo "       got exit $status and output: $output"
		failed=$((failed + 1))
	fi
}

run_certificate_test() {
	certificate_file=$WORK_DIR/google.der

	if ! command -v openssl >/dev/null 2>&1; then
		echo "[SKIP] google.com certificate: openssl not available"
		return
	fi

	if ! "$BINARY" -o "$certificate_file" google.com \
		>"$WORK_DIR/get_cert.out" 2>&1; then
		echo "[SKIP] google.com certificate: download unavailable"
		return
	fi

	if openssl asn1parse -inform DER -in "$certificate_file" \
		>"$WORK_DIR/asn1parse.out" 2>&1; then
		echo "[PASS] google.com certificate validated with openssl asn1parse"
		passed=$((passed + 1))
	else
		echo "[FAIL] google.com certificate failed openssl asn1parse"
		cat "$WORK_DIR/asn1parse.out"
		failed=$((failed + 1))
	fi
}

echo "Running get_cert command-line tests..."
run_test "Help" 0 "Usage:" -h
run_test "Missing hostname" 1 "Usage:" 
run_test "Missing port argument" 1 "Usage:" -p
run_test "Missing output argument" 1 "Usage:" -o
run_test "Unknown option" 1 "Usage:" -x example.com
run_test "Extra operand" 1 "Usage:" example.com extra
run_certificate_test

echo "Test summary: $passed passed, $failed failed."

[ "$failed" -eq 0 ]

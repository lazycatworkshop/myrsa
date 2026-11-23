#!/bin/sh

BINARY="./p7b_text"
TMPDIR=${TMPDIR:-/tmp}
WORK_DIR=$(mktemp -d "$TMPDIR/p7b_text-test.XXXXXX") || exit 1

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

: >"$WORK_DIR/empty.p7b"
printf '%s\n' '-----BEGIN PKCS7-----' 'AAAA' '-----END PKCS7-----' \
	>"$WORK_DIR/pem.p7b"
printf '\060\000' >"$WORK_DIR/empty_seq.p7b"

echo "Running p7b_text tests..."
run_test "Missing arguments" 1 "Usage:"
run_test "Unknown option" 1 "Usage:" -x foo
run_test "Missing option argument" 1 "Usage:" -f
run_test "Nonexistent file" 1 "Failed to open file" \
	-f "$WORK_DIR/nonexistent.p7b"
run_test "PEM encoded file" 1 "File is in PEM format" -f "$WORK_DIR/pem.p7b"
run_test "Empty file" 0 "" -f "$WORK_DIR/empty.p7b"
run_test "Malformed DER rejected" 1 "Failed to load contentType" \
	-f "$WORK_DIR/empty_seq.p7b"

if ! command -v openssl >/dev/null 2>&1; then
	echo "Skipping openssl-generated tests: openssl not found"
else
	key="$WORK_DIR/key.pem"
	cert="$WORK_DIR/cert.pem"
	p7b_pem="$WORK_DIR/bundle_pem.p7b"
	p7b_der="$WORK_DIR/bundle_der.p7b"

	if openssl req -x509 -newkey rsa:2048 -nodes -sha256 \
		-keyout "$key" -subj "/CN=test.example.com" -days 2 \
		-out "$cert" >/dev/null 2>&1 &&
		openssl crl2pkcs7 -nocrl -certfile "$cert" \
			-outform PEM -out "$p7b_pem" >/dev/null 2>&1 &&
		openssl crl2pkcs7 -nocrl -certfile "$cert" \
			-outform DER -out "$p7b_der" >/dev/null 2>&1 &&
		[ -s "$p7b_pem" ] && [ -s "$p7b_der" ]; then
		run_test "PEM PKCS#7 bundle rejected" 1 "File is in PEM format" \
			-f "$p7b_pem"
		run_test "DER PKCS#7 bundle accepted" 0 "" -f "$p7b_der"
	else
		echo "Skipping openssl-generated tests: unable to create PKCS#7 bundle"
	fi
fi

echo
echo "Passed: $passed, Failed: $failed"
[ "$failed" -eq 0 ]

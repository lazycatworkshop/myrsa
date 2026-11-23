#!/bin/sh

BINARY="./asn1parser"
TMPDIR=${TMPDIR:-/tmp}
WORK_DIR=$(mktemp -d "$TMPDIR/asn1parser-test.XXXXXX") || exit 1

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

printf '\060\003\002\001\005' >"$WORK_DIR/valid.der"
: >"$WORK_DIR/empty.der"
printf '\061\003\002\001\005' >"$WORK_DIR/wrong-tag.der"

certificate_host=www.wikipedia.org
certificate_file="$WORK_DIR/$certificate_host.der"
certificate_available=0

if command -v openssl >/dev/null 2>&1 &&
	openssl s_client -connect "$certificate_host:443" \
		-servername "$certificate_host" </dev/null 2>/dev/null |
	openssl x509 -outform DER -out "$certificate_file" 2>/dev/null &&
	[ -s "$certificate_file" ]; then
	certificate_available=1
fi

echo "Running ASN.1 parser tests..."
run_test "Valid DER" 0 "INTEGER" -f "$WORK_DIR/valid.der"
run_test "Verbose DER content" 0 "05" -v -f "$WORK_DIR/valid.der"
run_test "Missing filename" 1 "Usage: ./asn1parser -f <file> [-v]"
run_test "Empty file" 1 "file is empty" -f "$WORK_DIR/empty.der"
run_test "Wrong root tag is accepted as universal DER" 0 "INTEGER" -f "$WORK_DIR/wrong-tag.der"

if [ "$certificate_available" -eq 1 ]; then
	run_test "Website certificate ($certificate_host)" 0 "SEQUENCE" -f "$certificate_file"
else
	echo "[SKIP] Website certificate ($certificate_host): OpenSSL or network unavailable"
fi

echo "Test summary: $passed passed, $failed failed."

[ "$failed" -eq 0 ]

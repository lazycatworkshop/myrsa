#!/bin/sh

BINARY="./x509_extract_sig"
TMPDIR=${TMPDIR:-/tmp}
WORK_DIR=$(mktemp -d "$TMPDIR/x509_extract_sig-test.XXXXXX") || exit 1

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

run_test() {
	name=$1
	expected_exit=$2
	expected_output=$3
	shift 3

	output=$($BINARY "$@" 2>&1)
	status=$?

	if [ "$status" -eq "$expected_exit" ] &&
		echo "$output" | grep -F "$expected_output" >/dev/null 2>&1; then
		pass "$name"
	else
		fail "$name" "expected exit $expected_exit and output containing '$expected_output'; got exit $status: $output"
	fi
}

: >"$WORK_DIR/empty.der"
printf 'not a certificate' >"$WORK_DIR/garbage.der"

echo "Running x509_extract_sig tests..."
run_test "Missing arguments" 1 "Usage:"
run_test "Missing output option" 1 "Usage:" -c "$WORK_DIR/empty.der"
run_test "Missing input option" 1 "Usage:" -s "$WORK_DIR/out.sig"
run_test "Unknown option" 1 "Usage:" -x foo
run_test "Nonexistent certificate" 1 "Unable to open certificate file" \
	-c "$WORK_DIR/nonexistent.der" -s "$WORK_DIR/out.sig"
run_test "Empty certificate" 1 "Unable to read certificate" \
	-c "$WORK_DIR/empty.der" -s "$WORK_DIR/out.sig"
run_test "Garbage certificate" 1 "Unable to process X.509 certificate" \
	-c "$WORK_DIR/garbage.der" -s "$WORK_DIR/out.sig"

if ! command -v openssl >/dev/null 2>&1; then
	echo "Skipping valid certificate tests: openssl not found"
else
	for bits in 2048 4096; do
		key="$WORK_DIR/key$bits.pem"
		cert="$WORK_DIR/cert$bits.der"
		sig="$WORK_DIR/cert$bits.sig"
		name="RSA-$bits self-signed certificate"
		siglen=$((bits / 8))

		if ! openssl req -x509 -newkey "rsa:$bits" -nodes -sha256 \
			-keyout "$key" -subj "/CN=test.example.com" -days 2 \
			-outform DER -out "$cert" >/dev/null 2>&1 ||
			[ ! -s "$cert" ]; then
			echo "Skipping $name: unable to generate certificate"
			continue
		fi

		output=$($BINARY -c "$cert" -s "$sig" 2>&1)
		status=$?
		if [ "$status" -ne 0 ]; then
			fail "$name: extraction" "exit $status: $output"
			continue
		fi
		pass "$name: extraction"

		# The signature is the trailing bytes of the DER certificate
		if [ "$(wc -c <"$sig" | tr -d ' ')" -eq "$siglen" ]; then
			pass "$name: signature length is $siglen"
		else
			fail "$name: signature length is $siglen" \
				"got $(wc -c <"$sig" | tr -d ' ')"
		fi

		tail -c "$siglen" "$cert" >"$WORK_DIR/expected.sig"
		if cmp -s "$sig" "$WORK_DIR/expected.sig"; then
			pass "$name: signature matches certificate tail"
		else
			fail "$name: signature matches certificate tail"
		fi
	done
fi

echo
echo "Test summary: $passed passed, $failed failed."
[ "$failed" -eq 0 ]

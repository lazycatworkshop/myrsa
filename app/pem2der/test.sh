#!/bin/sh

BINARY=./pem2der
passed=0
failed=0
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/pem2der.XXXXXX") || exit 1
trap 'rm -rf "$tmpdir"' 0
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

hex_of() {
	od -An -v -tx1 "$1" | tr -d ' \n'
}

check_output() {
	name=$1
	input=$2
	expected=$3
	output="$tmpdir/output.der"
	printf '%b' "$input" >"$tmpdir/input.pem"

	if "$BINARY" -p "$tmpdir/input.pem" -d "$output" >/dev/null 2>&1; then
		got=$(hex_of "$output")
		if [ "$got" = "$expected" ]; then
			pass "$name"
		else
			fail "$name" "expected $expected, got $got"
		fi
	else
		fail "$name" "converter returned a failure status"
	fi
}

check_failure() {
	name=$1
	shift
	if "$BINARY" "$@" >/dev/null 2>&1; then
		fail "$name" "expected a non-zero exit status"
	else
		pass "$name"
	fi
}

echo "Running pem2der command-line tests..."
check_output "Decode base64 with PEM framing and preamble" \
	"Preamble\n-----BEGIN TEST-----\nSGVsbG8=\n-----END TEST-----\n" \
	"48656c6c6f"
check_output "Decode data split across lines" \
	"-----BEGIN TEST-----\nTWFu\n-----END TEST-----\n" \
	"4d616e"

: >"$tmpdir/empty.pem"
check_failure "Empty input file" -p "$tmpdir/empty.pem" -d "$tmpdir/empty.der"
printf 'no PEM header here\n' >"$tmpdir/no-header.pem"
check_failure "Missing PEM header" -p "$tmpdir/no-header.pem" -d "$tmpdir/no-header.der"
printf '%s\n' '-----BEGIN TEST-----' 'SGVsbG8!' '-----END TEST-----' >"$tmpdir/invalid.pem"
check_failure "Invalid base64 data" -p "$tmpdir/invalid.pem" -d "$tmpdir/invalid.der"
check_failure "Missing -p option" -d "$tmpdir/output.der"
check_failure "Missing -d option" -p "$tmpdir/input.pem"
check_failure "Unknown option" -x

echo "Test summary: $passed passed, $failed failed."
[ "$failed" -eq 0 ]

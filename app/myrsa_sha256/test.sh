#!/bin/sh

BINARY=./myrsa_sha256

passed=0
failed=0
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/myrsa_sha256.XXXXXX") || exit 1
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

# check_hash <name> <input file> <expected hex>
check_hash() {
	out="$tmpdir/out.bin"
	rm -f "$out"
	"$BINARY" -i "$2" -o "$out" >/dev/null 2>&1
	status=$?
	if [ "$status" -ne 0 ]; then
		fail "$1" "unexpected exit status $status"
		return
	fi
	got=$(hex_of "$out")
	if [ "$got" = "$3" ]; then
		pass "$1"
	else
		fail "$1" "expected $3, got $got"
	fi
}

# check_fail <name> <args...>
check_fail() {
	name=$1
	shift
	"$BINARY" "$@" >/dev/null 2>&1
	status=$?
	if [ "$status" -ne 0 ]; then
		pass "$name"
	else
		fail "$name" "expected non-zero exit status"
	fi
}

echo "Running myrsa_sha256 tests..."

printf 'abc' >"$tmpdir/abc.txt"
check_hash "SHA-256 of 'abc'" "$tmpdir/abc.txt" \
	ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

printf 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq' >"$tmpdir/two_block.txt"
check_hash "SHA-256 of 448-bit message" "$tmpdir/two_block.txt" \
	248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1

# Output must always be 32 bytes
"$BINARY" -i "$tmpdir/abc.txt" -o "$tmpdir/size.bin" >/dev/null 2>&1
size=$(wc -c <"$tmpdir/size.bin" | tr -d ' ')
if [ "$size" -eq 32 ]; then
	pass "Output is 32 bytes"
else
	fail "Output is 32 bytes" "got $size bytes"
fi

: >"$tmpdir/empty.txt"
check_fail "Empty input file" -i "$tmpdir/empty.txt" -o "$tmpdir/o.bin"
check_fail "Missing input file" -i "$tmpdir/nonexistent" -o "$tmpdir/o.bin"
check_fail "Missing -o option" -i "$tmpdir/abc.txt"
check_fail "Missing -i option" -o "$tmpdir/o.bin"
check_fail "Unknown option" -x

echo "Test summary: $passed passed, $failed failed."

[ "$failed" -eq 0 ]

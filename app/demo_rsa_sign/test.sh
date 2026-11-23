#!/bin/sh

# test.sh - Test script for demo_rsa_sign

BINARY=./demo_rsa_sign

passed=0
failed=0
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/demo_rsa_sign.XXXXXX") || exit 1
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

# check_sign <name> <file> <d> <n> <expected crc> <expected digest> <expected sig>
check_sign() {
	name=$1
	out=$("$BINARY" -d "$3" -n "$4" -f "$2" 2>&1)
	status=$?
	if [ "$status" -ne 0 ]; then
		fail "$name" "unexpected exit status $status"
		return
	fi
	crc=$(printf '%s\n' "$out" | sed -n 's/^CRC-32: //p')
	digest=$(printf '%s\n' "$out" | sed -n 's/^Digest: //p')
	sig=$(printf '%s\n' "$out" | sed -n 's/^Signature: //p')
	if [ "$crc" = "$5" ] && [ "$digest" = "$6" ] && [ "$sig" = "$7" ]; then
		pass "$name"
	else
		fail "$name" "expected $5/$6/$7, got $crc/$digest/$sig"
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

printf 'hello\n' >"$tmpdir/hello.txt"
printf '123456789' >"$tmpdir/check.txt"
printf 'The quick brown fox jumps over the lazy dog\n' >"$tmpdir/fox.txt"
: >"$tmpdir/empty.txt"

echo "Running demo_rsa_sign test suite..."
echo "========================================"

# Keys: p = 65521, q = 65519, n = 4292870399, e = 65537, d = 1475213633
N=4292870399
D=1475213633
check_sign "hello" "$tmpdir/hello.txt" $D $N 909783072 909783072 3787270918
check_sign "CRC-32 check string" "$tmpdir/check.txt" $D $N 3421780262 3421780262 4154687566
check_sign "fox" "$tmpdir/fox.txt" $D $N 1838399800 1838399800 693565110

# Textbook keys: p = 61, q = 53, n = 3233, d = 2753; digest is reduced mod n
check_sign "small modulus hello" "$tmpdir/hello.txt" 2753 3233 909783072 707 981
check_sign "small modulus check string" "$tmpdir/check.txt" 2753 3233 3421780262 2159 84

# Verification: signature^e mod n must equal the digest
if [ -x ../demo_rsa_trapdoor/demo_rsa_trapdoor ]; then
	res=$(../demo_rsa_trapdoor/demo_rsa_trapdoor -m 3787270918 -k 65537 -n $N 2>&1 | sed -n 's/^Result: //p')
	if [ "$res" = "909783072" ]; then
		pass "signature verifies with public key"
	else
		fail "signature verifies with public key" "got '$res'"
	fi
fi

echo "========================================"
echo "Testing invalid inputs..."
echo "========================================"

check_fail "no arguments"
check_fail "missing document" -d $D -n $N
check_fail "missing modulus" -d $D -f "$tmpdir/hello.txt"
check_fail "missing exponent" -n $N -f "$tmpdir/hello.txt"
check_fail "zero exponent" -d 0 -n $N -f "$tmpdir/hello.txt"
check_fail "zero modulus" -d $D -n 0 -f "$tmpdir/hello.txt"
check_fail "modulus 1" -d $D -n 1 -f "$tmpdir/hello.txt"
check_fail "modulus too large" -d $D -n 4294967296 -f "$tmpdir/hello.txt"
check_fail "negative exponent" -d -5 -n $N -f "$tmpdir/hello.txt"
check_fail "non-numeric exponent" -d abc -n $N -f "$tmpdir/hello.txt"
check_fail "unknown option" -x 1 -d $D -n $N -f "$tmpdir/hello.txt"
check_fail "nonexistent document" -d $D -n $N -f "$tmpdir/nope.txt"

# An empty document is valid: CRC-32 is 0 and so is the signature
check_sign "empty document" "$tmpdir/empty.txt" $D $N 0 0 0

echo "========================================"
echo "Passed: $passed, Failed: $failed"

[ "$failed" -eq 0 ]

#!/bin/sh

# test.sh - Test script for myrsa_trapdoor

BINARY="./myrsa_trapdoor"

if [ ! -x "$BINARY" ]; then
    echo "Error: Binary '$BINARY' not found or not executable. Compile it first." >&2
    exit 1
fi

TMPDIR=$(mktemp -d) || exit 1
trap 'rm -rf "$TMPDIR"' EXIT INT TERM HUP

passed=0
failed=0

# Strip whitespace and leading zeros so output compares numerically.
normalize() {
    printf '%s' "$1" | tr -d ' \n' | sed 's/^0*//'
}

# run_test NAME EXPECTED_EXIT EXPECTED_HEX ARGS...
run_test() {
    name="$1"
    expected_exit="$2"
    expected_hex="$3"
    shift 3

    output=$($BINARY "$@" 2>&1)
    status=$?
    ok=1

    if [ "$status" -ne "$expected_exit" ]; then
        echo "[FAIL] $name: Expected exit code $expected_exit, got $status"
        ok=0
    elif [ "$expected_exit" -eq 0 ]; then
        got=$(normalize "$output")
        want=$(normalize "$expected_hex")
        if [ "$got" != "$want" ]; then
            echo "[FAIL] $name: Expected '$want', got '$got'"
            ok=0
        fi
    elif [ -z "$output" ]; then
        echo "[FAIL] $name: Expected error message but got none"
        ok=0
    fi

    if [ "$ok" -eq 1 ]; then
        echo "[PASS] $name"
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi
}

# Keys are PKCS #1 RSAPublicKey: SEQUENCE { INTEGER modulus, INTEGER exponent }.
# n=3233 (0x0ca1), e=17
printf '\060\007\002\002\014\241\002\001\021' > "$TMPDIR/key_3233_17.der"
# n=5, e=3
printf '\060\006\002\001\005\002\001\003' > "$TMPDIR/key_5_3.der"
# Modulus tag is not INTEGER (OCTET STRING)
printf '\060\006\004\001\005\002\001\003' > "$TMPDIR/key_bad_modulus.der"
# Exponent tag is not INTEGER
printf '\060\006\002\001\005\004\001\003' > "$TMPDIR/key_bad_exp.der"
# Missing SEQUENCE wrapper
printf '\002\001\005\002\001\003' > "$TMPDIR/key_no_seq.der"

# m=65
printf '\101' > "$TMPDIR/msg_65.bin"
# m=2
printf '\002' > "$TMPDIR/msg_2.bin"
# Empty message
: > "$TMPDIR/msg_empty.bin"
: > "$TMPDIR/key_empty.der"

echo "Running myrsa_trapdoor test suite..."

# 65^17 mod 3233 = 2790 = 0x0ae6
run_test "encrypt 65 (n=3233,e=17)" 0 "0ae6" \
    -m "$TMPDIR/msg_65.bin" -k "$TMPDIR/key_3233_17.der"
# 2^3 mod 5 = 3
run_test "2^3 mod 5" 0 "03" \
    -m "$TMPDIR/msg_2.bin" -k "$TMPDIR/key_5_3.der"

run_test "no arguments" 1 ""
run_test "missing key option" 1 "" -m "$TMPDIR/msg_2.bin"
run_test "missing message option" 1 "" -k "$TMPDIR/key_5_3.der"
run_test "unknown option" 1 "" -x foo
run_test "nonexistent message file" 1 "" \
    -m "$TMPDIR/nope.bin" -k "$TMPDIR/key_5_3.der"
run_test "nonexistent key file" 1 "" \
    -m "$TMPDIR/msg_2.bin" -k "$TMPDIR/nope.der"
run_test "empty message file" 1 "" \
    -m "$TMPDIR/msg_empty.bin" -k "$TMPDIR/key_5_3.der"
run_test "empty key file" 1 "" \
    -m "$TMPDIR/msg_2.bin" -k "$TMPDIR/key_empty.der"
run_test "missing SEQUENCE wrapper" 1 "" \
    -m "$TMPDIR/msg_2.bin" -k "$TMPDIR/key_no_seq.der"
run_test "bad modulus tag" 1 "" \
    -m "$TMPDIR/msg_2.bin" -k "$TMPDIR/key_bad_modulus.der"
run_test "bad exponent tag" 1 "" \
    -m "$TMPDIR/msg_2.bin" -k "$TMPDIR/key_bad_exp.der"

echo ""
echo "Test summary: $passed passed, $failed failed."

[ "$failed" -eq 0 ]

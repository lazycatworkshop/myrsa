#!/bin/sh

BINARY=./demo_rsa_keys

passed=0
failed=0
trap 'exit 1' 1 2 3 15

if [ ! -x "$BINARY" ]; then
	echo "Error: Binary '$BINARY' not found or not executable. Compile it first." >&2
	exit 1
fi

run_test() {
	name=$1
	expected_exit=$2
	input=$3
	expected_output=$4

	output=$(printf '%s' "$input" | "$BINARY" 2>&1)
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

echo "Running RSA key generation tests..."
run_test "Two prime inputs" 0 "$(printf '61\n53\n')" "Public Key: (67, 3233)"
run_test "Private key generation" 0 "$(printf '61\n53\n')" "Private Key: (1723, 3233)"
run_test "Composite first input" 1 "$(printf '60\n')" "Error: 60 is not a prime number."
run_test "Composite second input" 1 "$(printf '61\n55\n')" "Error: 55 is not a prime number."

echo "Test summary: $passed passed, $failed failed."

[ "$failed" -eq 0 ]
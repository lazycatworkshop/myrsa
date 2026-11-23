#!/bin/sh

# test_rsa.sh - Test script for demo_rsa_trapdoor

BINARY="./demo_rsa_trapdoor"

if [ ! -x "$BINARY" ]; then
    echo "Error: Binary '$BINARY' not found or not executable. Compile it first." >&2
    exit 1
fi

passed=0
failed=0

run_test() {
    name="$1"
    expected_exit="$2"
    expected_output="$3"
    shift 3  # Remove the first three arguments (name, expected_exit, expected_output)
    
    # Run the binary with remaining arguments
    output=$($BINARY "$@" 2>&1)
    status=$?
    
    # Extract the result value from output if successful
    result=$(echo "$output" | grep "Result:" | sed 's/Result: //')
    
    # Check if test passed
    test_passed=0
    
    # Check exit status
    if [ "$status" -ne "$expected_exit" ]; then
        echo "[FAIL] $name: Expected exit code $expected_exit, got $status"
        test_passed=1
    fi
    
    # Check result for successful cases (exit code 0)
    if [ "$expected_exit" -eq 0 ]; then
        if [ "$result" != "$expected_output" ]; then
            echo "[FAIL] $name: Expected result '$expected_output', got '$result'"
            test_passed=1
        fi
    else
        # For failure cases, just check that we got a non-zero exit
        # and that there's some error output
        if [ -z "$output" ]; then
            echo "[FAIL] $name: Expected error message but got none"
            test_passed=1
        fi
    fi
    
    if [ "$test_passed" -eq 0 ]; then
        echo "[PASS] $name"
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi
}

echo "Running RSA trapdoor test suite..."
echo "========================================"

# Valid test cases (all should succeed)
# Test 1: Basic computation
# M = 4, K = 13, N = 77 -> 4^13 mod 77 = 53
run_test "Basic computation" 0 "53" -m 4 -k 13 -n 77

# Test 2: Identity operation (message^1 mod n)
# M = 42, K = 1, N = 100 -> 42^1 mod 100 = 42
run_test "Identity operation" 0 "42" -m 42 -k 1 -n 100

# Test 3: Square operation
# M = 5, K = 2, N = 100 -> 5^2 mod 100 = 25
run_test "Square operation" 0 "25" -m 5 -k 2 -n 100

# Test 4: Large exponent
# M = 2, K = 10, N = 1000 -> 2^10 mod 1000 = 24
run_test "Large exponent" 0 "24" -m 2 -k 10 -n 1000

# Test 5: RSA encryption example
# M = 7, E = 5, N = 33 -> 7^5 mod 33 = 10
run_test "RSA encryption" 0 "10" -m 7 -k 5 -n 33

# Test 6: Another RSA test
# M = 2, E = 17, N = 77 -> 2^17 mod 77 = 18
run_test "RSA test" 0 "18" -m 2 -k 17 -n 77

# Test 7: Large message (but less than modulus)
# M = 50, K = 3, N = 100 -> 50^3 mod 100 = 0
run_test "Large message" 0 "0" -m 50 -k 3 -n 100

# Test 8: Edge case - key=1 with large numbers
# M = 123456789, K = 1, N = 999999937
run_test "Edge case - key=1" 0 "123456789" -m 123456789 -k 1 -n 999999937

# Test 9: Message equals modulus - 1
# M = 99, K = 2, N = 100 -> 99^2 mod 100 = 1
run_test "Message = modulus-1" 0 "1" -m 99 -k 2 -n 100

# Test 10: Cube operation
# M = 3, K = 3, N = 50 -> 3^3 mod 50 = 27
run_test "Cube operation" 0 "27" -m 3 -k 3 -n 50

# Test 11: Large modulus with small numbers
# M = 10, K = 5, N = 97 -> 10^5 mod 97 = 90
run_test "Large modulus" 0 "90" -m 10 -k 5 -n 97

# Test 12: Message = 0? No, program rejects zero message
# So we'll test with message=1
# M = 1, K = 100, N = 1000 -> 1^100 mod 1000 = 1
run_test "Message = 1" 0 "1" -m 1 -k 100 -n 1000

echo "========================================"
echo "Testing invalid inputs..."
echo "========================================"

# Invalid test cases (all should fail)

# Test 13: Missing argument (should fail)
run_test "Missing arguments" 1 "" -m 4 -k 13

# Test 14: Zero modulus (should fail)
run_test "Zero modulus" 1 "" -m 4 -k 13 -n 0

# Test 15: Zero message (should fail)
run_test "Zero message" 1 "" -m 0 -k 13 -n 77

# Test 16: Zero key (should fail)
run_test "Zero key" 1 "" -m 4 -k 0 -n 77

# Test 17: Message greater than modulus (should fail)
run_test "Message >= Modulus" 1 "" -m 100 -k 13 -n 77

# Test 18: Invalid string arguments (should fail)
run_test "Invalid argument characters" 1 "" -m abc -k 13 -n 77

# Test 19: Message equals modulus (should fail)
run_test "Message equals modulus" 1 "" -m 77 -k 13 -n 77

# Test 20: Message with modulus wrapping (should fail because 12 >= 10)
run_test "Message >= modulus (wrapping)" 1 "" -m 12 -k 2 -n 10

# Test 21: Negative number format (should fail - strtoull may parse it weirdly)
run_test "Negative number" 1 "" -m -5 -k 13 -n 77

echo "========================================"
echo ""
echo "Test summary: $passed passed, $failed failed."

[ "$failed" -eq 0 ]

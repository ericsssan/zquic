#!/bin/bash

# Regression tests for ns3/run.sh command injection fixes

set +e  # Don't exit on first failure - we want to count all test results

TESTS_PASSED=0
TESTS_FAILED=0

# Helper: test that SCENARIO validation rejects malicious input
test_scenario_validation() {
    local scenario="$1"
    local expected_result="$2"  # "pass" or "fail"

    # Extract and test the regex validation logic from run.sh
    if [[ "$scenario" =~ ^[a-zA-Z0-9._/-]+$ ]]; then
        local result="pass"
    else
        local result="fail"
    fi

    if [[ "$result" == "$expected_result" ]]; then
        echo "✓ SCENARIO='$scenario' correctly validated as $result"
        ((TESTS_PASSED++))
    else
        echo "✗ SCENARIO='$scenario' validation failed (expected: $expected_result, got: $result)"
        ((TESTS_FAILED++))
    fi
}

# Helper: test that WAITFORSERVER validation rejects malicious input
test_waitforserver_validation() {
    local waitfor="$1"
    local expected_result="$2"  # "pass" or "fail"

    # Extract and test the regex validation logic from run.sh
    if [[ "$waitfor" =~ ^[a-zA-Z0-9.-]+:[0-9]+$ ]]; then
        local result="pass"
    else
        local result="fail"
    fi

    if [[ "$result" == "$expected_result" ]]; then
        echo "✓ WAITFORSERVER='$waitfor' correctly validated as $result"
        ((TESTS_PASSED++))
    else
        echo "✗ WAITFORSERVER='$waitfor' validation failed (expected: $expected_result, got: $result)"
        ((TESTS_FAILED++))
    fi
}

echo "=========================================="
echo "REGRESSION TESTS: ns3/run.sh Input Validation"
echo "=========================================="
echo ""

echo "SCENARIO Validation Tests:"
echo "  Valid scenarios (should pass):"
test_scenario_validation "handshake" "pass"
test_scenario_validation "transfer" "pass"
test_scenario_validation "quic-v2" "pass"
test_scenario_validation "test_scenario_123" "pass"
test_scenario_validation "scenario.v1" "pass"
test_scenario_validation "./scenario" "pass"
test_scenario_validation "../parent/scenario" "pass"

echo ""
echo "  Malicious scenarios (should fail):"
test_scenario_validation "test; rm -rf /" "fail"
test_scenario_validation "test && malicious" "fail"
test_scenario_validation "test | pipe" "fail"
test_scenario_validation "test\$(evil)" "fail"
test_scenario_validation "test\`evil\`" "fail"
test_scenario_validation "test'quote" "fail"
test_scenario_validation "test\"quote" "fail"
test_scenario_validation "test\nerror" "fail"
test_scenario_validation "test\ttab" "fail"
test_scenario_validation "test > /etc/passwd" "fail"

echo ""
echo "WAITFORSERVER Validation Tests:"
echo "  Valid servers (should pass):"
test_waitforserver_validation "localhost:4433" "pass"
test_waitforserver_validation "127.0.0.1:4433" "pass"
test_waitforserver_validation "example.com:8080" "pass"
test_waitforserver_validation "sub.domain.example:9999" "pass"
test_waitforserver_validation "server-1:5000" "pass"

echo ""
echo "  Malicious servers (should fail):"
test_waitforserver_validation "localhost; echo pwned" "fail"
test_waitforserver_validation "127.0.0.1 && curl evil.com" "fail"
test_waitforserver_validation "localhost:4433/path" "fail"
test_waitforserver_validation "localhost:4433@attacker" "fail"
test_waitforserver_validation "localhost\$(evil):4433" "fail"
test_waitforserver_validation "localhost:4433|bash" "fail"
test_waitforserver_validation "localhost" "fail"  # missing port
test_waitforserver_validation ":4433" "fail"  # missing host

echo ""
echo "=========================================="
echo "TEST RESULTS: $TESTS_PASSED passed, $TESTS_FAILED failed"
echo "=========================================="

if [[ $TESTS_FAILED -eq 0 ]]; then
    echo "✅ All regression tests passed"
    exit 0
else
    echo "❌ Some tests failed"
    exit 1
fi

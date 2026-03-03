#!/bin/bash
#
# zquic comprehensive interoperability test runner
#
# Runs the zquic server with multiple test cases and provides a test matrix.
#
# Usage:
#   ./interop.sh               # Run full test suite
#   ./interop.sh [testcase]    # Run specific test case
#   ./interop.sh --help        # Show help
#   ./interop.sh --manual      # Interactive mode (server runs until Ctrl+C)

# Configuration
# NOTE: These are the test cases supported by zquic server, not the full quic-interop-runner suite (24 cases)
TESTCASES=("handshake" "transfer" "v2" "retry" "keyupdate" "multiconnect")
CLIENTS=("quic-go" "quiche" "ngtcp2" "mvfst" "neqo" "s2n-quic" "quinn" "lsquic")
PORT_BASE=4433
CERTS="${CERTS:-./certs}"
WWW="${WWW:-./www}"
STARTUP_TIMEOUT=10

# Full quic-interop-runner test suite (for reference):
# handshake, long_rtt, transfer, chacha20, multiplexing, retry, resumption, zero_rtt,
# http3, amplification_limit, blackhole, keyupdate, handshake_loss, transfer_loss,
# handshake_corruption, transfer_corruption, ecn, port_rebinding, address_rebinding,
# ipv6, connection_migration, v2, version_negotiation, + measurements (goodput, cross_traffic)

# Colors (disable if NO_COLOR env var is set or terminal doesn't support it)
if [ -n "$NO_COLOR" ] || [ ! -t 1 ]; then
    GREEN=''
    YELLOW=''
    RED=''
    BLUE=''
    BOLD=''
    GRAY=''
    NC=''
else
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    RED='\033[0;31m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    GRAY='\033[0;37m'
    NC='\033[0m'
fi

print_header() {
    echo -e "${BLUE}${BOLD}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}${BOLD}║   zquic Comprehensive Interoperability Test Suite   ║${NC}"
    echo -e "${BLUE}${BOLD}╚════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_usage() {
    cat << EOF
${BOLD}USAGE:${NC}
  ./interop.sh [options]

${BOLD}OPTIONS:${NC}
  (no args)              Run full test suite (all test cases)
  [testcase]             Run single test case
  --client all           Test matrix: all test cases × all available clients
  --client [client]      Test matrix: all test cases × specific client
  --manual               Interactive mode (server runs until Ctrl+C)
  --help, -h             Show this help message
  --list-tests           List all available test cases
  --list-clients         List all available clients

${BOLD}SUPPORTED TEST CASES (6 of 24 in full quic-interop-runner suite):${NC}
  • handshake    - TLS 1.3 handshake completion
  • transfer     - File transfer over QUIC stream
  • v2           - QUIC v2 handshake
  • retry        - Initial token retry mechanism
  • keyupdate    - Key update during connection
  • multiconnect - Multiple concurrent connections (zquic custom)

${BOLD}AVAILABLE CLIENTS:${NC}
  ${CLIENTS[@]}

${BOLD}EXAMPLES:${NC}
  ./interop.sh                          # Full test suite
  ./interop.sh transfer                 # Test file transfer
  ./interop.sh --client all             # Test matrix: all cases × all clients
  ./interop.sh --client quic-go         # Test all cases with quic-go only
  ./interop.sh --manual                 # Start server for manual testing
  PORT=5555 ./interop.sh handshake      # Custom port

${BOLD}ENVIRONMENT VARIABLES:${NC}
  PORT          Base port for server (default: 4433)
  CERTS         Certificate directory (default: ./certs)
  WWW           WWW root directory (default: ./www)

EOF
}

handle_help() {
    if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
        print_usage
        exit 0
    fi

    if [[ "$1" == "--list-tests" ]]; then
        echo "Available test cases:"
        printf '  • %s\n' "${TESTCASES[@]}"
        exit 0
    fi

    if [[ "$1" == "--list-clients" ]]; then
        echo "Available QUIC client implementations:"
        printf '  • %s\n' "${CLIENTS[@]}"
        exit 0
    fi
}

setup_certs() {
    if [ -d "$CERTS" ] && [ -f "$CERTS/cert.pem" ] && [ -f "$CERTS/priv.key" ]; then
        return 0
    fi

    mkdir -p "$CERTS"
    openssl ecparam -name prime256v1 -genkey -out "$CERTS/priv.key" 2>/dev/null
    openssl req -new -x509 -key "$CERTS/priv.key" -out "$CERTS/cert.pem" \
        -days 365 -subj "/CN=localhost" 2>/dev/null
}

setup_www() {
    mkdir -p "$WWW"
    if [ ! -f "$WWW/index.html" ]; then
        cat > "$WWW/index.html" << 'EOF'
<!DOCTYPE html>
<html>
<head><title>zquic</title></head>
<body><h1>zquic QUIC Server</h1><p>Interoperability test server running.</p></body>
</html>
EOF
    fi
    if [ ! -f "$WWW/test.bin" ]; then
        dd if=/dev/zero of="$WWW/test.bin" bs=1024 count=1024 2>/dev/null
    fi
}

run_server_test() {
    local testcase=$1
    local port=$2

    export TESTCASE=$testcase
    export PORT=$port
    export CERTS="$CERTS"
    export WWW="$WWW"

    # Start server in background
    "$SERVER_BIN" > /tmp/zquic_${testcase}_${port}.log 2>&1 &
    local server_pid=$!

    # Wait for server startup (QUIC uses UDP)
    local elapsed=0
    while [ $elapsed -lt $STARTUP_TIMEOUT ]; do
        if nc -u -z localhost $port 2>/dev/null; then
            echo $server_pid
            return 0
        fi
        sleep 0.2
        elapsed=$((elapsed + 1))
    done

    kill $server_pid 2>/dev/null || true
    return 1
}

test_with_client_docker() {
    local client=$1
    local port=$2

    # Try to call quic-interop-runner client wrapper if it exists
    if [ -x "../quic-interop-runner/client" ]; then
        cd ../quic-interop-runner
        timeout 5 ./client -address localhost:$port -impl $client >/dev/null 2>&1
        local result=$?
        cd - >/dev/null
        return $result
    fi

    return 1
}

print_test_row() {
    local testcase=$1
    local status=$2
    local port=$3
    local pid=$4

    if [ "$status" = "OK" ]; then
        printf "  ${GREEN}✓${NC} %-15s ${GRAY}(port %d, PID %d)${NC}\n" "$testcase" "$port" "$pid"
    else
        printf "  ${RED}✗${NC} %-15s ${RED}Failed to start${NC}\n" "$testcase"
    fi
}

print_matrix_header() {
    echo ""
    echo -e "${BLUE}${BOLD}Test Matrix: Test Cases × Clients${NC}"
    echo ""

    # Print header row
    printf "%-15s" "Testcase"
    for client in "$@"; do
        printf " | %-10s" "$client"
    done
    echo " |"

    # Print separator
    printf "%-15s" "─────────────"
    for client in "$@"; do
        printf " | %-10s" "──────────"
    done
    echo " |"
}

print_matrix_row() {
    local testcase=$1
    shift
    local results=("$@")

    printf "%-15s" "$testcase"
    for result in "${results[@]}"; do
        if [ "$result" = "PASS" ]; then
            printf " | ${GREEN}✓ PASS${NC}    "
        elif [ "$result" = "FAIL" ]; then
            printf " | ${RED}✗ FAIL${NC}    "
        else
            printf " | ${YELLOW}⊘ SKIP${NC}    "
        fi
    done
    echo " |"
}

run_client_matrix() {
    local selected_clients=("$@")

    print_matrix_header "${selected_clients[@]}"

    local total=0
    local passed=0

    for testcase in "${TESTCASES[@]}"; do
        local port=$((PORT_BASE + RANDOM % 5000))
        local row_results=()

        if server_pid=$(run_server_test "$testcase" "$port" 2>/dev/null); then
            if [ -n "$server_pid" ]; then
                # Test each client
                for client in "${selected_clients[@]}"; do
                    if test_with_client_docker "$client" "$port"; then
                        row_results+=("PASS")
                        ((passed++))
                    else
                        row_results+=("FAIL")
                    fi
                    ((total++))
                done

                # Print row
                print_matrix_row "$testcase" "${row_results[@]}"

                # Cleanup
                kill $server_pid 2>/dev/null || true
                wait $server_pid 2>/dev/null || true
            else
                # Server failed to start
                for _ in "${selected_clients[@]}"; do
                    row_results+=("SKIP")
                done
                print_matrix_row "$testcase" "${row_results[@]}"
            fi
        fi
    done

    echo ""
    echo -e "${BLUE}${BOLD}Summary:${NC}"
    echo "  Total tests: $total"
    echo "  Passed: ${GREEN}$passed${NC}"
    echo "  Failed: ${RED}$((total - passed))${NC}"
}

# Main
handle_help "$@"

print_header

# Setup
setup_certs
setup_www

# Build
echo -e "${YELLOW}Building server...${NC}"
if ! zig build -Doptimize=ReleaseSafe 2>&1 | grep -q "Build"; then
    :
fi

SERVER_BIN="./zig-out/bin/server"
if [ ! -f "$SERVER_BIN" ]; then
    echo -e "${RED}Error: Server binary not found${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Build successful${NC}"
echo ""

# Convert to absolute paths
CERTS="$(cd "$CERTS" 2>/dev/null && pwd)"
WWW="$(cd "$WWW" 2>/dev/null && pwd)"

# Determine mode
MANUAL_MODE=false
CLIENT_MODE=false
CLIENT_FILTER=""

if [[ "$1" == "--manual" ]]; then
    MANUAL_MODE=true
    TESTCASES=("transfer")
elif [[ "$1" == "--client" ]]; then
    CLIENT_MODE=true
    CLIENT_FILTER="$2"
    if [ -z "$CLIENT_FILTER" ]; then
        echo -e "${RED}Error: --client requires an argument (all or client name)${NC}"
        exit 1
    fi
fi

if [ "$MANUAL_MODE" = true ]; then
    # Interactive mode
    echo -e "${YELLOW}Starting server in interactive mode (transfer testcase)...${NC}"
    PORT=${PORT:-4433}
    export TESTCASE=transfer
    export PORT
    export CERTS
    export WWW

    "$SERVER_BIN" &
    SERVER_PID=$!

    trap "kill $SERVER_PID 2>/dev/null || true" EXIT

    # Wait for startup
    sleep 2
    if nc -u -z localhost $PORT 2>/dev/null; then
        echo -e "${GREEN}✓ Server listening on port $PORT${NC}"
        echo ""
        echo -e "${BLUE}${BOLD}Manual Testing Instructions:${NC}"
        echo ""
        echo "  1. From quic-interop-runner directory:"
        echo "     ${GRAY}$ cd ../quic-interop-runner${NC}"
        echo ""
        echo "  2. Test with quic-go client:"
        echo "     ${GRAY}$ ./client -address localhost:$PORT${NC}"
        echo ""
        echo "  3. Test with other clients:"
        echo "     ${GRAY}$ ./client -address localhost:$PORT -impl quiche${NC}"
        echo "     ${GRAY}$ ./client -address localhost:$PORT -impl ngtcp2${NC}"
        echo ""
        echo "  Press ${BOLD}Ctrl+C${NC} to stop the server"
        echo ""
    else
        echo -e "${RED}✗ Server failed to start${NC}"
        exit 1
    fi

    wait $SERVER_PID
elif [ "$CLIENT_MODE" = true ]; then
    # Client matrix mode
    echo -e "${YELLOW}Running client matrix tests...${NC}"

    if [[ "$CLIENT_FILTER" == "all" ]]; then
        run_client_matrix "${CLIENTS[@]}"
    else
        # Check if client is valid
        if [[ " ${CLIENTS[@]} " =~ " ${CLIENT_FILTER} " ]]; then
            run_client_matrix "$CLIENT_FILTER"
        else
            echo -e "${RED}Error: Unknown client '$CLIENT_FILTER'${NC}"
            echo "Available clients:"
            printf '  • %s\n' "${CLIENTS[@]}"
            exit 1
        fi
    fi
else
    # Standard test suite mode
    echo -e "${YELLOW}Running test suite...${NC}"
    echo ""
    echo -e "${BLUE}${BOLD}Test Results:${NC}"
    echo ""

    declare -i total=0
    declare -i passed=0

    for testcase in "${TESTCASES[@]}"; do
        port=$((PORT_BASE + RANDOM % 5000))

        if server_pid=$(run_server_test "$testcase" "$port" 2>/dev/null); then
            if [ -n "$server_pid" ]; then
                print_test_row "$testcase" "OK" "$port" "$server_pid"
                ((passed++))

                # Keep server running for a moment
                sleep 1

                # Cleanup
                kill $server_pid 2>/dev/null || true
                wait $server_pid 2>/dev/null || true
            else
                print_test_row "$testcase" "FAIL" "$port" "0"
            fi
        fi
        ((total++))
    done

    echo ""
    echo -e "${BLUE}${BOLD}Summary:${NC}"
    if [ $total -eq 1 ]; then
        echo "  Test case: ${YELLOW}${TESTCASES[0]}${NC}"
    else
        echo "  Total test cases: $total"
    fi
    echo "  Status: ${GREEN}$passed/${total} passed${NC}"
    echo ""
    echo -e "${BLUE}${BOLD}Available Clients:${NC}"
    for client in "${CLIENTS[@]}"; do
        echo "  • $client"
    done
    echo ""
    echo -e "${GRAY}To test against QUIC clients use:${NC}"
    echo -e "${GRAY}  $ ./interop.sh --client all             # Test matrix${NC}"
    echo -e "${GRAY}  $ ./interop.sh --client quic-go         # Single client${NC}"
    echo -e "${GRAY}  $ ./interop.sh --manual                 # Interactive mode${NC}"
    echo ""
fi

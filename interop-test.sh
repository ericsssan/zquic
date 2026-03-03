#!/bin/bash
#
# COMPREHENSIVE QUIC INTEROPERABILITY TEST AUTOMATION
#
# Fully automated end-to-end test runner that:
#   1. Checks all prerequisites
#   2. Clones quic-interop-runner if missing
#   3. Builds zquic from source
#   4. Builds Docker image
#   5. Runs full test suite (24+ test cases)
#   6. Displays matrix results
#
# Usage:
#   ./run-full-interop.sh                 # Full automation
#   ./run-full-interop.sh --help          # Show help
#   ./run-full-interop.sh --skip-build    # Use existing builds
#   ./run-full-interop.sh --skip-clone    # Don't clone interop-runner

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZQUIC_DIR="$SCRIPT_DIR"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"
INTEROP_DIR="$PARENT_DIR/quic-interop-runner"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Flags
SKIP_BUILD=false
SKIP_CLONE=false
CLIENTS="all"  # Default: run all clients

print_header() {
    echo -e "${BLUE}${BOLD}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}${BOLD}    ZQUIC COMPREHENSIVE INTEROPERABILITY TEST AUTOMATION${NC}"
    echo -e "${BLUE}${BOLD}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GRAY}Testing zquic QUIC server against multiple client implementations${NC}"
    echo ""
}

print_usage() {
    cat << EOF
${BOLD}USAGE:${NC}
  ./interop-test.sh [options]

${BOLD}OPTIONS:${NC}
  (no args)              Full automation: all clients (clone/build/test)
  --help                 Show this help message
  --skip-build           Skip building zquic & Docker image (use existing)
  --skip-clone           Don't clone quic-interop-runner (assume it exists)
  --client all           Test against all QUIC clients (default)
  --client CLIENT_NAME   Test against specific client only
  --clients C1,C2,C3     Test against multiple clients (comma-separated)

${BOLD}WHAT THIS SCRIPT DOES:${NC}
  1. ✓ Verify all system prerequisites
  2. ✓ Clone quic-interop-runner if missing
  3. ✓ Install Python dependencies
  4. ✓ Compile zquic server
  5. ✓ Build zquic Docker image
  6. ✓ Run full 24+ test case suite
  7. ✓ Generate & display test matrix
  8. ✓ Save detailed logs

${BOLD}PREREQUISITES (auto-checked):${NC}
  • Zig compiler (zig --version)
  • Docker (docker --version)
  • Docker Compose (docker compose version)
  • Python 3 (python3 --version)
  • Git (git --version)

${BOLD}AVAILABLE QUIC CLIENTS:${NC}
  quic-go, quiche, ngtcp2, mvfst, neqo, s2n-quic, quinn, lsquic

${BOLD}TEST SUITE:${NC}
  24+ QUIC interoperability test cases
  Results: ✓ (passed) ✕ (failed) ? (unsupported)

${BOLD}EXAMPLES:${NC}
  # Full automation with all clients
  ./interop-test.sh

  # Test against all clients (skip rebuild)
  ./interop-test.sh --skip-build

  # Test against specific client
  ./interop-test.sh --client quic-go
  ./interop-test.sh --client quiche

  # Test against multiple specific clients
  ./interop-test.sh --clients quic-go,quiche,ngtcp2

  # If you already cloned quic-interop-runner
  ./interop-test.sh --skip-clone --client quic-go

  # Help
  ./interop-test.sh --help

${BOLD}TIME ESTIMATE:${NC}
  • First run: 30-60 minutes (clone, build, test)
  • Subsequent: 20-40 minutes (test only with --skip-build)

${BOLD}OUTPUT:${NC}
  Logs: ../quic-interop-runner/logs_<timestamp>/
  Matrix: Displayed in terminal after tests complete

EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            print_usage
            exit 0
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --skip-clone)
            SKIP_CLONE=true
            shift
            ;;
        --client)
            if [[ $# -lt 2 ]]; then
                echo -e "${RED}Error: --client requires an argument${NC}"
                exit 1
            fi
            CLIENTS="$2"
            shift 2
            ;;
        --clients)
            if [[ $# -lt 2 ]]; then
                echo -e "${RED}Error: --clients requires an argument${NC}"
                exit 1
            fi
            CLIENTS="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            print_usage
            exit 1
            ;;
    esac
done

# ============================================================================
# PHASE 1: CHECK PREREQUISITES
# ============================================================================
phase_check_prerequisites() {
    echo -e "${YELLOW}[PHASE 1/7] Checking prerequisites...${NC}"
    echo ""

    local all_ok=true

    # Check Zig
    if command -v zig &> /dev/null; then
        echo -e "${GREEN}✓${NC} Zig compiler"
    else
        echo -e "${RED}✗${NC} Zig compiler (required)"
        all_ok=false
    fi

    # Check Docker
    if command -v docker &> /dev/null; then
        echo -e "${GREEN}✓${NC} Docker"
    else
        echo -e "${RED}✗${NC} Docker (required)"
        all_ok=false
    fi

    # Check Docker Compose
    if command -v docker-compose &> /dev/null || docker compose version &> /dev/null; then
        echo -e "${GREEN}✓${NC} Docker Compose"
    else
        echo -e "${RED}✗${NC} Docker Compose (required)"
        all_ok=false
    fi

    # Check Python 3
    if command -v python3 &> /dev/null; then
        echo -e "${GREEN}✓${NC} Python 3"
    else
        echo -e "${RED}✗${NC} Python 3 (required)"
        all_ok=false
    fi

    # Check Git
    if command -v git &> /dev/null; then
        echo -e "${GREEN}✓${NC} Git"
    else
        echo -e "${RED}✗${NC} Git (required for cloning)"
        all_ok=false
    fi

    echo ""
    if [ "$all_ok" = false ]; then
        echo -e "${RED}Missing required tools. Please install them first.${NC}"
        exit 1
    fi
    echo -e "${GREEN}All prerequisites satisfied${NC}"
    echo ""
}

# ============================================================================
# PHASE 2: SETUP QUIC-INTEROP-RUNNER
# ============================================================================
phase_setup_interop_runner() {
    if [ "$SKIP_CLONE" = true ]; then
        echo -e "${YELLOW}[PHASE 2/7] Skipping quic-interop-runner setup (--skip-clone)${NC}"
        echo ""
        return
    fi

    echo -e "${YELLOW}[PHASE 2/7] Setting up quic-interop-runner...${NC}"
    echo ""

    if [ -d "$INTEROP_DIR" ]; then
        echo -e "${GREEN}✓${NC} quic-interop-runner already exists"
    else
        echo -e "${YELLOW}  • Cloning quic-interop-runner...${NC}"
        if git clone https://github.com/quic-interop/quic-interop-runner.git "$INTEROP_DIR" > /dev/null 2>&1; then
            echo -e "${GREEN}✓${NC} Cloned quic-interop-runner"
        else
            echo -e "${RED}✗${NC} Failed to clone quic-interop-runner"
            exit 1
        fi
    fi

    # Install Python dependencies
    echo -e "${YELLOW}  • Installing Python dependencies...${NC}"
    cd "$INTEROP_DIR"
    if python3 -m pip install -q -r requirements.txt > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Python dependencies installed"
    else
        echo -e "${YELLOW}⚠${NC} Warning: Some Python dependencies may not have installed cleanly"
    fi

    echo ""
}

# ============================================================================
# PHASE 3: BUILD ZQUIC
# ============================================================================
phase_build_zquic() {
    if [ "$SKIP_BUILD" = true ]; then
        echo -e "${YELLOW}[PHASE 3/7] Skipping zquic build (--skip-build)${NC}"
        echo ""
        return
    fi

    echo -e "${YELLOW}[PHASE 3/7] Building zquic server...${NC}"
    echo ""

    cd "$ZQUIC_DIR"

    echo -e "${YELLOW}  • Compiling zquic with Zig...${NC}"
    if zig build -Doptimize=ReleaseSafe > /tmp/zig_build.log 2>&1; then
        echo -e "${GREEN}✓${NC} zquic compiled successfully"
    else
        echo -e "${RED}✗${NC} Failed to compile zquic"
        echo "Build log:"
        cat /tmp/zig_build.log
        exit 1
    fi

    # Verify binary exists
    if [ -f "$ZQUIC_DIR/zig-out/bin/server" ]; then
        echo -e "${GREEN}✓${NC} Server binary created ($(ls -lh "$ZQUIC_DIR/zig-out/bin/server" | awk '{print $5}'))"
    else
        echo -e "${RED}✗${NC} Server binary not found"
        exit 1
    fi

    echo ""
}

# ============================================================================
# PHASE 4: BUILD DOCKER IMAGE
# ============================================================================
phase_build_docker() {
    if [ "$SKIP_BUILD" = true ]; then
        echo -e "${YELLOW}[PHASE 4/7] Skipping Docker image build (--skip-build)${NC}"
        echo ""
        return
    fi

    echo -e "${YELLOW}[PHASE 4/7] Building zquic Docker image...${NC}"
    echo ""

    cd "$ZQUIC_DIR"

    # macOS: Fix keychain issue
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo -e "${YELLOW}  • Fixing macOS keychain...${NC}"
        security unlock-keychain ~/Library/Keychains/login.keychain-db 2>/dev/null || true
    fi

    # Check if image already exists
    if docker image inspect zquic:latest > /dev/null 2>&1; then
        echo -e "${YELLOW}  • Removing old Docker image...${NC}"
        docker image rm zquic:latest > /dev/null 2>&1 || true
    fi

    echo -e "${YELLOW}  • Building Docker image (this may take a minute)...${NC}"
    if docker build -t zquic:latest -f tools/Dockerfile . > /tmp/docker_build.log 2>&1; then
        echo -e "${GREEN}✓${NC} Docker image built successfully"
        local image_size=$(docker image inspect zquic:latest --format='{{.Size}}' | numfmt --to=iec 2>/dev/null || echo "?")
        echo -e "${GRAY}  Size: $image_size${NC}"
    else
        echo -e "${RED}✗${NC} Failed to build Docker image"
        echo ""
        echo "Build log (last 30 lines):"
        tail -30 /tmp/docker_build.log
        echo ""
        echo -e "${YELLOW}Troubleshooting (macOS keychain issue):${NC}"
        if grep -q "keychain" /tmp/docker_build.log; then
            echo "  Option 1: Unlock keychain manually"
            echo "    security unlock-keychain ~/Library/Keychains/login.keychain-db"
            echo "    ./interop-test.sh"
            echo ""
            echo "  Option 2: Disable Docker credential storage"
            echo "    1. Open Docker Desktop → Settings"
            echo "    2. Go to Advanced tab"
            echo "    3. Uncheck 'Securely store Docker logins'"
            echo "    4. Restart Docker"
            echo "    5. ./interop-test.sh"
        fi
        exit 1
    fi

    echo ""
}

# ============================================================================
# PHASE 5: VERIFY SETUP
# ============================================================================
phase_verify_setup() {
    echo -e "${YELLOW}[PHASE 5/7] Verifying setup...${NC}"
    echo ""

    # Verify interop-runner
    if [ ! -f "$INTEROP_DIR/interop.py" ]; then
        echo -e "${RED}✗${NC} quic-interop-runner not properly installed"
        exit 1
    fi
    echo -e "${GREEN}✓${NC} quic-interop-runner ready"

    # Verify Docker image
    if ! docker image inspect zquic:latest > /dev/null 2>&1; then
        echo -e "${RED}✗${NC} zquic Docker image not found"
        exit 1
    fi
    echo -e "${GREEN}✓${NC} zquic Docker image ready"

    # Verify implementations.json includes zquic
    if grep -q '"zquic"' "$INTEROP_DIR/implementations.json"; then
        echo -e "${GREEN}✓${NC} zquic registered in implementations.json"
    else
        echo -e "${YELLOW}⚠${NC} zquic not in implementations.json, adding it..."
        python3 << 'PYTHON_SCRIPT'
import json
config_file = '$INTEROP_DIR/implementations.json'
with open(config_file, 'r') as f:
    config = json.load(f)
if 'zquic' not in config:
    config['zquic'] = {
        "image": "zquic:latest",
        "url": "https://github.com/openquic/zquic",
        "role": "server"
    }
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)
PYTHON_SCRIPT
        echo -e "${GREEN}✓${NC} zquic added to implementations.json"
    fi

    echo ""
}

# ============================================================================
# PHASE 6: RUN TEST SUITE
# ============================================================================
phase_run_tests() {
    echo -e "${YELLOW}[PHASE 6/7] Running test suite...${NC}"
    echo ""
    echo -e "${GRAY}This will test zquic against QUIC clients.${NC}"
    echo -e "${GRAY}Clients: $CLIENTS${NC}"
    echo -e "${GRAY}Test cases: handshake, transfer, v2, retry, keyupdate, + 19 more...${NC}"
    echo ""

    cd "$INTEROP_DIR"

    # Run interop tests with run.py
    echo -e "${YELLOW}Starting tests (streaming output below)...${NC}"
    echo -e "${GRAY}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""

    LOG_TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    LOG_DIR="logs_$LOG_TIMESTAMP"

    # Build the client list for run.py
    if [ "$CLIENTS" = "all" ]; then
        CLIENT_ARG=""  # Empty means use all clients in run.py
    else
        CLIENT_ARG="-c $CLIENTS"
    fi

    # Run with unbuffered output - stream to both console and log file
    python3 -u run.py -s zquic $CLIENT_ARG -l $LOG_DIR 2>&1 | while IFS= read -r line; do
        echo "$line"
        echo "$line" >> /tmp/interop_test_output.log

        # Highlight important lines
        if echo "$line" | grep -q "Running test case:"; then
            echo -e "${BLUE}  ➜ $line${NC}"
        elif echo "$line" | grep -q "Saving logs\|Run took"; then
            echo -e "${GREEN}  ✓ $line${NC}"
        fi
    done

    EXIT_CODE=${PIPESTATUS[0]}

    echo ""
    echo -e "${GRAY}═══════════════════════════════════════════════════════════════════${NC}"

    if [ $EXIT_CODE -eq 0 ]; then
        echo -e "${GREEN}✓${NC} Test suite completed successfully"
    else
        echo -e "${YELLOW}⚠${NC} Test suite finished with exit code $EXIT_CODE (see logs for details)"
    fi

    echo ""
}

# ============================================================================
# PHASE 7: DISPLAY RESULTS
# ============================================================================
phase_display_results() {
    echo -e "${YELLOW}[PHASE 7/7] Processing results...${NC}"
    echo ""

    cd "$INTEROP_DIR"

    # Find latest log directory
    LATEST_LOG=$(ls -td logs_* 2>/dev/null | head -1)

    if [ -z "$LATEST_LOG" ]; then
        echo -e "${YELLOW}No test logs found${NC}"
        return
    fi

    echo -e "${BLUE}${BOLD}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}${BOLD}TEST RESULTS MATRIX${NC}"
    echo -e "${BLUE}${BOLD}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}Timestamp:${NC} $LATEST_LOG"
    echo -e "${YELLOW}Location:${NC} $(pwd)/$LATEST_LOG"
    echo ""

    # Parse and display consolidated test results
    echo -e "${BOLD}Test Results Summary:${NC}"
    echo ""

    python3 << 'PYTHON_SCRIPT'
import re
import os
from pathlib import Path

output_file = "/tmp/interop_test_output.log"
log_dir = Path("$LATEST_LOG")

# Parse output log for run.py matrix format
if not os.path.exists(output_file):
    print("  No test output found")
else:
    with open(output_file, 'r') as f:
        content = f.read()

    # Find all result lines with clients
    # Format: | client-name | ✓() ... | or | client-name | ?(X) ... | or | client-name | ✕(X) ... |
    client_results = {}

    # Extract all lines with client names and their results
    for line in content.split('\n'):
        # Match table rows with client names
        if '| ' in line and ('✓' in line or '✕' in line or '?' in line):
            # Extract client name (first column)
            parts = line.split('|')
            if len(parts) >= 2:
                client = parts[1].strip()
                if client and client not in ['', 'zquic']:
                    # Extract all test status indicators for this client
                    remaining = '|'.join(parts[2:])

                    # Count pass/fail/unsupported across all columns
                    passed = remaining.count('✓')
                    failed = 0
                    unsupported = 0

                    # Extract failed test codes
                    failed_match = re.search(r'✕\(([^)]*)\)', remaining)
                    if failed_match:
                        failed_codes = failed_match.group(1)
                        if failed_codes:
                            failed = len(failed_codes.split(','))

                    # Extract unsupported test codes
                    unsupported_match = re.search(r'\?\(([^)]*)\)', remaining)
                    if unsupported_match:
                        unsupported_codes = unsupported_match.group(1)
                        if unsupported_codes:
                            unsupported = len(unsupported_codes.split(','))

                    if passed > 0 or failed > 0 or unsupported > 0:
                        total = passed + failed + unsupported
                        pass_rate = (passed / total * 100) if total > 0 else 0
                        client_results[client] = {
                            'passed': passed,
                            'failed': failed,
                            'unsupported': unsupported,
                            'total': total,
                            'pass_rate': pass_rate
                        }

    if client_results:
        print("  Results by Client:")
        print("  " + "─" * 70)

        # Calculate aggregate stats
        total_all = sum(r['total'] for r in client_results.values())
        passed_all = sum(r['passed'] for r in client_results.values())
        failed_all = sum(r['failed'] for r in client_results.values())
        unsupported_all = sum(r['unsupported'] for r in client_results.values())
        pass_rate_all = (passed_all / total_all * 100) if total_all > 0 else 0

        for client in sorted(client_results.keys()):
            r = client_results[client]
            status = f"{r['passed']}✓ {r['failed']}✕ {r['unsupported']}?"
            print(f"  {client:15} │ {status:20} │ {r['pass_rate']:6.1f}% │ ({r['total']} tests)")

        print("  " + "─" * 70)
        status_all = f"{passed_all}✓ {failed_all}✕ {unsupported_all}?"
        print(f"  {'AGGREGATE':15} │ {status_all:20} │ {pass_rate_all:6.1f}% │ ({total_all} tests)")
        print("")

    else:
        # Fallback to single-client parsing if no matrix found
        passed_match = re.search(r'✓\(\)', content)
        failed_match = re.search(r'✕\(([^)]+)\)', content)
        unsupported_match = re.search(r'\?\(([^)]+)\)', content)

        passed_tests = 1 if passed_match else 0
        failed_list = failed_match.group(1).split(',') if failed_match else []
        unsupported_list = unsupported_match.group(1).split(',') if unsupported_match else []

        total_tests = passed_tests + len(failed_list) + len(unsupported_list)
        pass_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0

        print(f"  Total Test Cases:     {total_tests}")
        print(f"  Passed (✓):           {passed_tests}")
        print(f"  Failed (✕):           {len(failed_list)}")
        print(f"  Unsupported (?):      {len(unsupported_list)}")
        print(f"  Pass Rate:            {pass_rate:.1f}%")
        print("")

PYTHON_SCRIPT

    echo ""
    echo -e "${BOLD}Accessing Detailed Logs:${NC}"
    echo ""
    echo -e "${GRAY}Test logs directory:${NC}"
    echo "  $(pwd)/$LATEST_LOG"
    echo ""
    echo -e "${GRAY}For debugging failed tests:${NC}"
    echo "  cd ../quic-interop-runner/$LATEST_LOG"
    echo "  ls -la                          # List zquic x client pairs"
    echo "  cd zquic_quic-go/transfer/      # Check passed test"
    echo "  cat */output.txt                # View test output"
    echo "  cat server/keys.log             # TLS secrets (Wireshark)"
    echo "  cat client/log.txt              # Client logs"
    echo "  wireshark sim/trace_node_right.pcap  # Packet capture"
    echo ""

    echo -e "${BLUE}${BOLD}═══════════════════════════════════════════════════════════════════${NC}"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
main() {
    print_header

    phase_check_prerequisites
    phase_setup_interop_runner
    phase_build_zquic
    phase_build_docker
    phase_verify_setup
    phase_run_tests
    phase_display_results

    echo ""
    echo -e "${GREEN}${BOLD}✓ FULL INTEROPERABILITY TEST AUTOMATION COMPLETED${NC}"
    echo ""
}

main

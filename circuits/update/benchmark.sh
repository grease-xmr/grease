#!/usr/bin/env bash
#
# Benchmark script for GreaseUpdate Noir circuit
# Measures compilation time, execution time, and circuit metrics
#
# Usage: ./benchmark.sh [--prove] [--iterations N]
#
# Options:
#   --prove       Also run proof generation (requires bb)
#   --iterations  Number of iterations for timing (default: 3)

set -euo pipefail

# Configuration
ITERATIONS=5
RUN_PROVE=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --prove)
            RUN_PROVE=true
            shift
            ;;
        --iterations)
            ITERATIONS="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--prove] [--iterations N]"
            echo ""
            echo "Options:"
            echo "  --prove       Also run proof generation (requires bb)"
            echo "  --iterations  Number of iterations for timing (default: 5)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
BOLD='\033[1m'

print_header() {
    echo ""
    echo -e "${BLUE}${BOLD}========================================${NC}"
    echo -e "${BLUE}${BOLD}  $1${NC}"
    echo -e "${BLUE}${BOLD}========================================${NC}"
}

print_section() {
    echo ""
    echo -e "${CYAN}--- $1 ---${NC}"
}

print_metric() {
    printf "  ${YELLOW}%-24s${NC} %s\n" "$1:" "$2"
}

print_time() {
    printf "  ${GREEN}%-24s${NC} %.3fs\n" "$1:" "$2"
}

# Check for nargo
if ! command -v nargo &> /dev/null; then
    echo -e "${RED}Error: nargo not found in PATH${NC}"
    exit 1
fi

# Get version info
NARGO_VERSION=$(nargo --version | head -1 | awk '{print $4}')

print_header "GreaseUpdate Circuit Benchmark"

echo ""
echo -e "${BOLD}Configuration:${NC}"
print_metric "Noir version" "$NARGO_VERSION"
print_metric "Iterations" "$ITERATIONS"
print_metric "Proof generation" "$([ "$RUN_PROVE" = true ] && echo 'enabled' || echo 'disabled')"

# ============================================================================
# Circuit Info
# ============================================================================
print_section "Circuit Metrics (nargo info)"

INFO_OUTPUT=$(nargo info 2>&1)

# Parse ACIR opcodes and Brillig opcodes from the table
# Table format: | Package | Function | Expression Width | ACIR Opcodes | Brillig Opcodes |
MAIN_LINE=$(echo "$INFO_OUTPUT" | grep -E "^\| GreaseUpdate\s+\| main")
ACIR_OPCODES=$(echo "$MAIN_LINE" | awk -F'|' '{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $5); print $5}')
BRILLIG_OPCODES=$(echo "$MAIN_LINE" | awk -F'|' '{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $6); print $6}')
EXPRESSION_WIDTH=$(echo "$MAIN_LINE" | awk -F'|' '{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $4); print $4}')

print_metric "ACIR Opcodes" "${ACIR_OPCODES:-N/A}"
print_metric "Brillig Opcodes" "${BRILLIG_OPCODES:-N/A}"
print_metric "Expression Width" "${EXPRESSION_WIDTH:-N/A}"

# Show all functions in the circuit
echo ""
echo "  Full circuit breakdown:"
echo "$INFO_OUTPUT" | grep -E "^\|" | while read -r line; do
    echo "    $line"
done

# ============================================================================
# Compilation Benchmark
# ============================================================================
print_section "Compilation Benchmark ($ITERATIONS iterations)"

# Clean first
rm -rf target/

COMPILE_TIMES=()
for i in $(seq 1 "$ITERATIONS"); do
    rm -rf target/
    START=$(date +%s.%N)
    nargo compile > /dev/null 2>&1
    END=$(date +%s.%N)
    ELAPSED=$(echo "$END - $START" | bc)
    COMPILE_TIMES+=("$ELAPSED")
    printf "    Iteration %d: %.3fs\n" "$i" "$ELAPSED"
done

# Calculate average
COMPILE_SUM=0
for t in "${COMPILE_TIMES[@]}"; do
    COMPILE_SUM=$(echo "$COMPILE_SUM + $t" | bc)
done
COMPILE_AVG=$(echo "scale=3; $COMPILE_SUM / $ITERATIONS" | bc)

echo ""
print_time "Average compile time" "$COMPILE_AVG"

# ============================================================================
# Execution Benchmark
# ============================================================================
print_section "Witness Generation Benchmark ($ITERATIONS iterations)"

# Ensure compiled first
nargo compile > /dev/null 2>&1

EXECUTE_TIMES=()
for i in $(seq 1 "$ITERATIONS"); do
    rm -f target/GreaseUpdate.gz
    START=$(date +%s.%N)
    nargo execute > /dev/null 2>&1
    END=$(date +%s.%N)
    ELAPSED=$(echo "$END - $START" | bc)
    EXECUTE_TIMES+=("$ELAPSED")
    printf "    Iteration %d: %.3fs\n" "$i" "$ELAPSED"
done

# Calculate average
EXECUTE_SUM=0
for t in "${EXECUTE_TIMES[@]}"; do
    EXECUTE_SUM=$(echo "$EXECUTE_SUM + $t" | bc)
done
EXECUTE_AVG=$(echo "scale=3; $EXECUTE_SUM / $ITERATIONS" | bc)

echo ""
print_time "Average execute time" "$EXECUTE_AVG"

# Check witness file size
if [ -f target/GreaseUpdate.gz ]; then
    WITNESS_SIZE=$(du -h target/GreaseUpdate.gz | cut -f1)
    print_metric "Witness file size" "$WITNESS_SIZE"
fi

# ============================================================================
# Test Benchmark
# ============================================================================
print_section "Test Benchmark (single run)"

START=$(date +%s.%N)
TEST_OUTPUT=$(nargo test )
END=$(date +%s.%N)
TEST_ELAPSED=$(echo "$END - $START" | bc)

TEST_COUNT=$(echo "$TEST_OUTPUT" | grep -oE '[0-9]+ tests passed' | grep -oE '[0-9]+')
print_time "All tests" "$TEST_ELAPSED"
print_metric "Tests passed" "${TEST_COUNT:-0}"

# ============================================================================
# Proof Generation Benchmark (optional)
# ============================================================================
if [ "$RUN_PROVE" = true ]; then
    print_section "Proof Generation Benchmark"

    if command -v bb &> /dev/null; then
        BB_VERSION=$(bb --version 2>&1 | head -1 || echo "unknown")
        print_metric "Barretenberg version" "$BB_VERSION"

        PROVE_TIMES=()
        for i in $(seq 1 "$ITERATIONS"); do
            START=$(date +%s.%N)
            nargo prove > /dev/null 2>&1 || true
            END=$(date +%s.%N)
            ELAPSED=$(echo "$END - $START" | bc)
            PROVE_TIMES+=("$ELAPSED")
            printf "    Iteration %d: %.3fs\n" "$i" "$ELAPSED"
        done

        # Calculate average
        PROVE_SUM=0
        for t in "${PROVE_TIMES[@]}"; do
            PROVE_SUM=$(echo "$PROVE_SUM + $t" | bc)
        done
        PROVE_AVG=$(echo "scale=3; $PROVE_SUM / $ITERATIONS" | bc)

        echo ""
        print_time "Average prove time" "$PROVE_AVG"

        # Check proof file size
        if [ -f proofs/GreaseUpdate.proof ]; then
            PROOF_SIZE=$(du -h proofs/GreaseUpdate.proof | cut -f1)
            print_metric "Proof file size" "$PROOF_SIZE"
        fi
    else
        echo -e "  ${YELLOW}Warning: bb (Barretenberg) not found, skipping proof generation${NC}"
    fi
fi

# ============================================================================
# Artifact Sizes
# ============================================================================
print_section "Artifact Sizes"

if [ -f target/GreaseUpdate.json ]; then
    JSON_SIZE=$(du -h target/GreaseUpdate.json | cut -f1)
    print_metric "Circuit JSON" "$JSON_SIZE"
fi

if [ -d target ]; then
    TOTAL_SIZE=$(du -sh target | cut -f1)
    print_metric "Total target dir" "$TOTAL_SIZE"
fi

# ============================================================================
# Summary
# ============================================================================
print_header "Summary"

echo ""
echo -e "${BOLD}Circuit Complexity:${NC}"
print_metric "ACIR Opcodes" "${ACIR_OPCODES:-N/A}"
print_metric "Brillig Opcodes" "${BRILLIG_OPCODES:-N/A}"

echo ""
echo -e "${BOLD}Timing (avg of $ITERATIONS runs):${NC}"
print_time "Compile" "$COMPILE_AVG"
print_time "Execute (witness gen)" "$EXECUTE_AVG"
if [ "$RUN_PROVE" = true ] && [ -n "${PROVE_AVG:-}" ]; then
    print_time "Prove" "$PROVE_AVG"
fi

echo ""
echo -e "${GREEN}Benchmark complete.${NC}"

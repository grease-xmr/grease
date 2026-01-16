#!/bin/bash
set -euo pipefail

# Test coverage script for Grease project
# Runs unit tests with coverage (excludes e2e and circuits)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
COVERAGE_DIR="$PROJECT_ROOT/target/coverage"

# Check if cargo-llvm-cov is installed
if ! command -v cargo-llvm-cov &> /dev/null; then
    echo "cargo-llvm-cov is not installed."
    echo "Install it with: cargo install cargo-llvm-cov"
    exit 1
fi

# Parse arguments
OUTPUT_FORMAT="html"
OPEN_REPORT=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --html)
            OUTPUT_FORMAT="html"
            shift
            ;;
        --lcov)
            OUTPUT_FORMAT="lcov"
            shift
            ;;
        --text)
            OUTPUT_FORMAT="text"
            shift
            ;;
        --open)
            OPEN_REPORT=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --html    Generate HTML report (default)"
            echo "  --lcov    Generate LCOV report"
            echo "  --text    Print text summary to stdout"
            echo "  --open    Open HTML report in browser after generation"
            echo "  -h,--help Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

cd "$PROJECT_ROOT"

echo "Running test coverage for Grease project..."
echo "Excluding: e2e, circuits"
echo ""

case $OUTPUT_FORMAT in
    html)
        mkdir -p "$COVERAGE_DIR"
        cargo llvm-cov \
            --all-features \
            --workspace \
            --exclude e2e \
            --exclude circuits \
            --release \
            --html \
            --output-dir "$COVERAGE_DIR/html"

        echo ""
        echo "Coverage report generated at: $COVERAGE_DIR/html/index.html"

        if $OPEN_REPORT; then
            if command -v xdg-open &> /dev/null; then
                xdg-open "$COVERAGE_DIR/html/index.html"
            elif command -v open &> /dev/null; then
                open "$COVERAGE_DIR/html/index.html"
            else
                echo "Could not detect a command to open the browser."
            fi
        fi
        ;;
    lcov)
        mkdir -p "$COVERAGE_DIR"
        cargo llvm-cov \
            --all-features \
            --workspace \
            --exclude e2e \
            --exclude circuits \
            --release \
            --lcov \
            --output-path "$COVERAGE_DIR/lcov.info"

        echo ""
        echo "LCOV report generated at: $COVERAGE_DIR/lcov.info"
        ;;
    text)
        cargo llvm-cov \
            --all-features \
            --workspace \
            --exclude e2e \
            --exclude circuits \
            --release
        ;;
esac

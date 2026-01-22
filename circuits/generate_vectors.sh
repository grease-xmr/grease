#!/bin/bash
#
# Generate test vectors for the VCOF circuit.
#
# This script runs the Noir test vector generator and parses the output
# into a CSV file for use in testing the Rust implementation.
#
# Usage:
#   ./generate_vectors.sh [OPTIONS]
#
# Options:
#   --count N         Number of vectors per index (default: 10, max: 10)
#   --indices "1,420" Comma-separated list of indices to generate (default: "1,420")
#   --chain           Also generate chain test vectors
#   --output FILE     Output file path (default: test_vectors.csv)
#   --help            Show this help message
#

set -e

# Default values
COUNT=10
INDICES="1,420"
GENERATE_CHAIN=false
OUTPUT_FILE="test_vectors.csv"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --count)
            COUNT="$2"
            shift 2
            ;;
        --indices)
            INDICES="$2"
            shift 2
            ;;
        --chain)
            GENERATE_CHAIN=true
            shift
            ;;
        --output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --help)
            sed -n '2,17p' "$0" | sed 's/^# //' | sed 's/^#//'
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validate count
if [[ ! "$COUNT" =~ ^[0-9]+$ ]] || [ "$COUNT" -lt 1 ] || [ "$COUNT" -gt 10 ]; then
    echo "Error: --count must be a number between 1 and 10"
    exit 1
fi

echo "=== VCOF Test Vector Generator ==="
echo "Indices: $INDICES"
echo "Count per index: $COUNT"
echo "Output file: $OUTPUT_FILE"
echo ""

# Change to circuits directory for nargo
cd "$SCRIPT_DIR"

# Create temporary file for raw output
TEMP_OUTPUT=$(mktemp)
trap "rm -f $TEMP_OUTPUT" EXIT

echo "Running Noir test to generate vectors..."
echo ""

# Run the main test vector generator
if ! nargo test generate_test_vectors --show-output --package GreaseLibrary 2>&1 | tee "$TEMP_OUTPUT"; then
    echo "Error: nargo test failed"
    exit 1
fi

echo ""
echo "Parsing output..."

# Extract vectors from output
# Each vector is output as:
#   VECTOR|0|<i>
#   VECTOR|1|<wn_prev>
#   VECTOR|2|<wn_next>
#   VECTOR|3|<pub_prev_x>
#   VECTOR|4|<pub_prev_y>
#   VECTOR|5|<pub_next_x>
#   VECTOR|6|<pub_next_y>
#   VECTOR|END
{
    # Write CSV header
    echo "i,wn_prev,wn_next,pub_prev_x,pub_prev_y,pub_next_x,pub_next_y"

    # Parse the test output using awk
    awk '
    BEGIN {
        field_count = 0
        fields[0] = ""
        fields[1] = ""
        fields[2] = ""
        fields[3] = ""
        fields[4] = ""
        fields[5] = ""
        fields[6] = ""
    }

    /^VECTOR\|[0-6]\|/ {
        # Extract field index and value
        split($0, parts, "|")
        idx = parts[2]
        val = parts[3]
        fields[idx] = val
        next
    }

    /^VECTOR\|END/ {
        # Output the complete vector as CSV
        print fields[0] "," fields[1] "," fields[2] "," fields[3] "," fields[4] "," fields[5] "," fields[6]
        # Reset for next vector
        for (i = 0; i <= 6; i++) {
            fields[i] = ""
        }
        next
    }
    ' "$TEMP_OUTPUT"

} > "$OUTPUT_FILE"

# Count generated vectors (excluding header)
VECTOR_COUNT=$(($(wc -l < "$OUTPUT_FILE") - 1))

echo ""
echo "=== Generation Complete ==="
echo "Generated $VECTOR_COUNT test vectors"
echo "Output written to: $OUTPUT_FILE"

# Show first few lines as preview
if [ "$VECTOR_COUNT" -gt 0 ]; then
    echo ""
    echo "Preview (first 5 vectors):"
    head -6 "$OUTPUT_FILE" | column -t -s','
fi

# Optionally generate chain vectors
if [ "$GENERATE_CHAIN" = true ]; then
    echo ""
    echo "Generating chain test vectors..."

    CHAIN_OUTPUT="${OUTPUT_FILE%.csv}_chain.csv"
    CHAIN_TEMP=$(mktemp)
    trap "rm -f $TEMP_OUTPUT $CHAIN_TEMP" EXIT

    if ! nargo test generate_chain_test_vectors --show-output --package GreaseLibrary 2>&1 | tee "$CHAIN_TEMP"; then
        echo "Error: chain test failed"
        exit 1
    fi

    {
        echo "i,wn_prev,wn_next,pub_prev_x,pub_prev_y,pub_next_x,pub_next_y"

        awk '
        BEGIN {
            field_count = 0
            fields[0] = ""
            fields[1] = ""
            fields[2] = ""
            fields[3] = ""
            fields[4] = ""
            fields[5] = ""
            fields[6] = ""
        }

        /^VECTOR\|[0-6]\|/ {
            split($0, parts, "|")
            idx = parts[2]
            val = parts[3]
            fields[idx] = val
            next
        }

        /^VECTOR\|END/ {
            print fields[0] "," fields[1] "," fields[2] "," fields[3] "," fields[4] "," fields[5] "," fields[6]
            for (i = 0; i <= 6; i++) {
                fields[i] = ""
            }
            next
        }
        ' "$CHAIN_TEMP"

    } > "$CHAIN_OUTPUT"

    CHAIN_COUNT=$(($(wc -l < "$CHAIN_OUTPUT") - 1))
    echo ""
    echo "Generated $CHAIN_COUNT chain test vectors"
    echo "Chain output written to: $CHAIN_OUTPUT"

    if [ "$CHAIN_COUNT" -gt 0 ]; then
        echo ""
        echo "Chain preview:"
        head -6 "$CHAIN_OUTPUT" | column -t -s','
    fi
fi

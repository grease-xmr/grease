#!/bin/bash
#
# Build the Grease whitepaper PDF from Typst sources.
#
# This script compiles docs/src/00_grease_whitepaper.typ into
# docs/grease_whitepaper.pdf using the Typst compiler.
#
# Options:
#   -h, --help    Show this help message and exit
#   -f, --format  Run typstyle formatter on .typ files before compiling
#   --fast        Skip sequence diagram compilation (faster builds)
#
# Examples:
#   ./build-docs.sh              # Standard build
#   ./build-docs.sh -f           # Format sources, then build
#   ./build-docs.sh --fast       # Quick build without diagrams
#   ./build-docs.sh -f --fast    # Format and quick build
#
# Requirements:
#   - typst (Typst compiler)
#   - typstyle (optional, for formatting)

set -e

usage() {
    sed -n '3,20p' "$0" | sed 's/^# \?//'
    exit 0
}

format() {
    if command -v typstyle >/dev/null 2>&1; then
        echo "typstyle found - running formatter..."
        typstyle -i -l140 --wrap-text docs/src/*.typ
    else
        echo "typstyle not found; skipping formatting step."
    fi
}

# Parse arguments
DO_FORMAT=0
FAST_FLAG=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            ;;
        -f|--format)
            DO_FORMAT=1
            shift
            ;;
        --fast)
            FAST_FLAG=1
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use -h or --help for usage information."
            exit 1
            ;;
    esac
done

if [[ $DO_FORMAT -eq 1 ]]; then
    format
fi

if [[ $FAST_FLAG -eq 1 ]]; then
    echo "Fast mode enabled. Sequence diagrams will not be compiled."
fi

echo "Building docs/grease_whitepaper.pdf..."
typst compile --root ./docs --input fast=$FAST_FLAG docs/src/00_grease_whitepaper.typ docs/grease_whitepaper.pdf
#!/bin/bash

# Coverage analysis script for Pinocchio fuzzer
set -e

echo "=== Pinocchio Fuzzer Coverage Analysis ==="
echo

# Check if we have profraw files
PROFRAW_FILES=$(find . -name "*.profraw" | wc -l)
echo "Found $PROFRAW_FILES .profraw files"

if [ "$PROFRAW_FILES" -eq 0 ]; then
    echo "No coverage data found. Run the fuzzer first to generate coverage data."
    exit 1
fi

# Create coverage directory
mkdir -p coverage

# Merge all profraw files into a single profdata file
echo "Merging coverage data..."
llvm-profdata merge -sparse *.profraw -o coverage/merged.profdata

# Generate coverage report
echo "Generating coverage report..."
llvm-cov show \
    --format=html \
    --output-dir=coverage/html \
    --show-line-counts-or-regions \
    --show-expansions \
    --show-instantiations \
    --instr-profile=coverage/merged.profdata \
    target/release/fuzz_deserialize

# Generate summary report
echo "Generating summary report..."
llvm-cov report \
    --instr-profile=coverage/merged.profdata \
    --summary-only \
    target/release/fuzz_deserialize > coverage/summary.txt

echo
echo "=== Coverage Summary ==="
cat coverage/summary.txt

echo
echo "=== Coverage Files Generated ==="
echo "HTML Report: coverage/html/index.html"
echo "Summary: coverage/summary.txt"
echo "Raw Data: coverage/merged.profdata"

echo
echo "To view the HTML report, open: file://$(pwd)/coverage/html/index.html"

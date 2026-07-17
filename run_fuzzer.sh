#!/bin/bash

# Simple fuzzer runner script
set -e

TARGET=${1:-fuzz_deserialize}
CORPUS_DIR="./corpus"
CRASHES_DIR="./corpus/crashes"
MAX_LEN=200

echo "Running $TARGET fuzzer..."

# Create directories
mkdir -p "$CORPUS_DIR"
mkdir -p "$CRASHES_DIR"

# Find the binary (check both debug and release)
if [[ -f "./target/release/$TARGET" ]]; then
    BINARY="./target/release/$TARGET"
elif [[ -f "./target/debug/$TARGET" ]]; then
    BINARY="./target/debug/$TARGET"
else
    echo "Error: $TARGET binary not found. Run ./compile_fuzzer.sh first."
    exit 1
fi

# Set up fuzzer arguments
ARGS="-max_len=$MAX_LEN"
ARGS="$ARGS -artifact_prefix=$CRASHES_DIR/"

# Run the fuzzer
echo "Binary: $BINARY"
echo "Corpus: $CORPUS_DIR"
echo "Crashes: $CRASHES_DIR"
echo "Max input: ${MAX_LEN} bytes"
echo "Running fuzzer..."

"$BINARY" $ARGS

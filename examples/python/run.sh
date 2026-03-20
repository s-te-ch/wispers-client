#!/usr/bin/env bash
# Run a Python example with the correct library and module paths.
# Usage: ./run.sh ping.py --storage /tmp/node-a --token <token>
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLIENT_DIR="$SCRIPT_DIR/../.."

# Build the native library if needed.
if [ ! -f "$CLIENT_DIR/target/debug/libwispers_connect.dylib" ] && \
   [ ! -f "$CLIENT_DIR/target/debug/libwispers_connect.so" ]; then
    echo "Building wispers-connect..."
    (cd "$CLIENT_DIR" && cargo build)
fi

export DYLD_LIBRARY_PATH="$CLIENT_DIR/target/debug${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
export LD_LIBRARY_PATH="$CLIENT_DIR/target/debug${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PYTHONPATH="$CLIENT_DIR/wrappers/python${PYTHONPATH:+:$PYTHONPATH}"

if [ $# -eq 0 ]; then
    echo "Usage: ./run.sh <script.py> [args...]"
    echo "Example: ./run.sh ping.py --storage /tmp/node-a --token <token>"
    exit 1
fi

SCRIPT="$1"
shift
exec python3 "$SCRIPT_DIR/$SCRIPT" "$@"

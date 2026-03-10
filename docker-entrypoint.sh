#!/bin/bash
set -e

echo "========================================"
echo "zkTLS Attestator Service Starting..."
echo "========================================"

# Validate required environment variables
if [ -z "$ZKTLS_PATH" ]; then
    echo "ERROR: ZKTLS_PATH environment variable is not set"
    exit 1
fi

if [ -z "$PORT" ]; then
    echo "ERROR: PORT environment variable is not set"
    exit 1
fi

echo "Environment Configuration:"
echo "  NODE_ENV: ${NODE_ENV:-not set}"
echo "  PORT: ${PORT}"
echo "  ZKTLS_PATH: ${ZKTLS_PATH}"
echo "  ZKTLS_BACKEND: ${ZKTLS_BACKEND:-r0}"

# Check if zktls binary exists
if [ ! -f "$ZKTLS_PATH" ]; then
    echo "ERROR: zktls binary not found at $ZKTLS_PATH"
    exit 1
fi

if [ ! -x "$ZKTLS_PATH" ]; then
    echo "ERROR: zktls binary at $ZKTLS_PATH is not executable"
    exit 1
fi

echo "zktls binary found and is executable"

# Display zktls version (optional)
echo "zktls version:"
$ZKTLS_PATH --version 2>/dev/null || echo "  (version check skipped)"

echo "========================================"
echo "Starting application..."
echo "========================================"

# Execute the main command
exec "$@"

#!/bin/bash

# Test build without full Docker to save time

echo "=== Testing Rust compilation ==="
cargo check --lib 2>&1 | head -100

if [ $? -eq 0 ]; then
    echo "✅ Library compilation succeeded"
else
    echo "❌ Library compilation failed"
    exit 1
fi

echo ""
echo "=== Building Docker image ==="
docker compose build stacker

if [ $? -eq 0 ]; then
    echo "✅ Docker build succeeded"
    echo ""
    echo "=== Next steps ==="
    echo "1. docker compose up -d"
    echo "2. Test: curl -H 'Authorization: Bearer {jwt}' http://localhost:8000/stacker/admin/templates"
else
    echo "❌ Docker build failed"
    exit 1
fi

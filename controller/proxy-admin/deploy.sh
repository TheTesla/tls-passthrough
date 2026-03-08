#!/bin/bash
# Always does a clean rebuild so file changes are picked up
set -e
echo "→ Stopping containers..."
docker compose down

echo "→ Rebuilding image (no cache)..."
docker compose build --no-cache

echo "→ Starting..."
docker compose up -d

echo "→ Logs (Ctrl+C to exit):"
docker compose logs -f

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$SCRIPT_DIR"

echo "Starting Docker services..."
docker compose up -d
trap 'docker compose down' EXIT

echo "Waiting for Xray server to be ready..."
for i in $(seq 1 120); do
    if nc -z 127.0.0.1 10443 2>/dev/null &&
       nc -z 127.0.0.1 19443 2>/dev/null &&
       nc -z 127.0.0.1 18080 2>/dev/null; then
        echo "Xray, TLS destination and echo server are ready."
        break
    fi
    if [ "$i" -eq 120 ]; then
        echo "Timed out waiting for Xray server."
        docker compose logs
        docker compose down
        exit 1
    fi
    sleep 1
done

echo "Running e2e tests..."
cd "$PROJECT_DIR"
TEST_EXIT=0
cargo test e2e -- --ignored 2>&1 || TEST_EXIT=$?

cd "$SCRIPT_DIR"
echo "Stopping Docker services..."
docker compose down

exit $TEST_EXIT

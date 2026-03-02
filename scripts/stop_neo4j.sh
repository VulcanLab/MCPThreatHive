#!/bin/bash
# Stop Neo4j Docker container

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "⚠️  Docker daemon is not running."
    echo "   Neo4j container may not be running either."
    exit 0
fi

echo "🛑 Stopping Neo4j Docker container..."

docker-compose -f docker-compose.neo4j.yml down

echo "✅ Neo4j stopped"


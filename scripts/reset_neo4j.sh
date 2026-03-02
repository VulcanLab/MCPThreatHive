#!/bin/bash
# Reset Neo4j (stop, remove volumes, and restart)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker daemon is not running. Please start Docker first."
    exit 1
fi

echo "⚠️  This will delete all Neo4j data!"
read -p "Are you sure? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Cancelled."
    exit 0
fi

echo "🛑 Stopping Neo4j..."
docker-compose -f docker-compose.neo4j.yml down -v

echo "🗑️  Removed Neo4j volumes"

echo "🚀 Starting fresh Neo4j instance..."
docker-compose -f docker-compose.neo4j.yml up -d

echo "✅ Neo4j reset complete!"
echo "🌐 Neo4j Browser: http://localhost:7474"


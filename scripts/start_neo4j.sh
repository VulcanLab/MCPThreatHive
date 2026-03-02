#!/bin/bash
# Start Neo4j Docker container independently

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

echo "🚀 Starting Neo4j Docker container..."
echo ""

# Check if Docker is installed
if ! command -v docker > /dev/null 2>&1; then
    echo "❌ Docker is not installed."
    echo "   Please install Docker Desktop: https://www.docker.com/products/docker-desktop"
    exit 1
fi

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker daemon is not running."
    echo ""
    echo "   Please start Docker Desktop:"
    echo "   - macOS: Open Docker Desktop application"
    echo "   - Linux: sudo systemctl start docker"
    echo "   - Windows: Start Docker Desktop from Start menu"
    echo ""
    echo "   After starting Docker, wait a few seconds and try again."
    exit 1
fi

# Check if Neo4j is already running
if docker ps | grep -q mcp-neo4j; then
    echo "⚠️  Neo4j container is already running!"
    echo ""
    echo "Container info:"
    docker ps | grep mcp-neo4j
    echo ""
    echo "To stop it: docker-compose -f docker-compose.neo4j.yml down"
    exit 0
fi

# Start Neo4j
docker-compose -f docker-compose.neo4j.yml up -d

# Wait for Neo4j to be ready
echo ""
echo "⏳ Waiting for Neo4j to be ready..."
sleep 5

# Check health
max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if docker exec mcp-neo4j cypher-shell -u neo4j -p password "RETURN 1" > /dev/null 2>&1; then
        echo "✅ Neo4j is ready!"
        break
    fi
    attempt=$((attempt + 1))
    echo "   Attempt $attempt/$max_attempts..."
    sleep 2
done

if [ $attempt -eq $max_attempts ]; then
    echo "⚠️  Neo4j may still be starting. Check logs with: docker-compose -f docker-compose.neo4j.yml logs"
fi

echo ""
echo "🌐 Neo4j Browser: http://localhost:7474"
echo "🔌 Bolt Connection: bolt://localhost:7687"
echo "👤 Username: neo4j"
echo "🔑 Password: password"
echo ""
echo "📝 Update your .env file:"
echo "   (NEO4J_URI defaults to bolt://localhost:7687 for local dev)"
echo "   NEO4J_USERNAME=neo4j"
echo "   NEO4J_PASSWORD=password"
echo ""
echo "To view logs: docker-compose -f docker-compose.neo4j.yml logs -f"
echo "To stop: docker-compose -f docker-compose.neo4j.yml down"


#!/bin/bash
# Check Docker status and provide helpful messages

echo "🔍 Checking Docker status..."
echo ""

# Check if Docker is installed
if ! command -v docker > /dev/null 2>&1; then
    echo "❌ Docker is not installed."
    echo ""
    echo "📥 Install Docker Desktop:"
    echo "   macOS:   https://www.docker.com/products/docker-desktop"
    echo "   Linux:   https://docs.docker.com/engine/install/"
    echo "   Windows: https://www.docker.com/products/docker-desktop"
    exit 1
fi

echo "✅ Docker is installed"

# Check if Docker daemon is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker daemon is not running."
    echo ""
    echo "🚀 To start Docker:"
    echo "   macOS:   Open Docker Desktop application"
    echo "   Linux:   sudo systemctl start docker"
    echo "   Windows: Start Docker Desktop from Start menu"
    echo ""
    echo "   After starting, wait a few seconds and try again."
    exit 1
fi

echo "✅ Docker daemon is running"
echo ""

# Show Docker version
echo "📦 Docker version:"
docker --version
docker-compose --version 2>/dev/null || echo "   (docker-compose not found, using 'docker compose' instead)"

echo ""
echo "✅ Docker is ready to use!"



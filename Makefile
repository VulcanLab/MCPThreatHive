# MCP Threat Platform Makefile

.PHONY: help install test run docker-build docker-up docker-down clean neo4j-up neo4j-down neo4j-logs neo4j-reset

help:
	@echo "MCP Threat Platform - Available commands:"
	@echo ""
	@echo "Main Application:"
	@echo "  make install      - Install dependencies"
	@echo "  make test         - Run tests"
	@echo "  make run          - Start development server"
	@echo "  make docker-build - Build Docker image"
	@echo "  make docker-up    - Start Docker containers"
	@echo "  make docker-down  - Stop Docker containers"
	@echo ""
	@echo "Neo4j (Standalone):"
	@echo "  make neo4j-up     - Start Neo4j Docker container"
	@echo "  make neo4j-down   - Stop Neo4j Docker container"
	@echo "  make neo4j-logs   - View Neo4j logs"
	@echo "  make neo4j-reset  - Reset Neo4j (delete all data)"
	@echo ""
	@echo "Utilities:"
	@echo "  make clean        - Clean temporary files"
	@echo "  make check-docker - Check Docker installation and status"

install:
	python3 -m venv venv || true
	. venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt

test:
	. venv/bin/activate && python test_server.py

run:
	. venv/bin/activate && python -m api.server

docker-build:
	docker build -t mcp-threat-platform:latest .

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

neo4j-up:
	@echo "Starting Neo4j..."
	@./scripts/start_neo4j.sh

neo4j-down:
	@echo "Stopping Neo4j..."
	@docker-compose -f docker-compose.neo4j.yml down

neo4j-logs:
	@docker-compose -f docker-compose.neo4j.yml logs -f

neo4j-reset:
	@./scripts/reset_neo4j.sh

check-docker:
	@./scripts/check_docker.sh

clean:
	find . -type d -name __pycache__ -exec rm -r {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete


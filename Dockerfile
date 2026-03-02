# MCP Threat Platform Dockerfile
# Supports amd64 and arm64 (Apple Silicon)

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=api.server
ENV FLASK_ENV=production

# Install system dependencies (works on both amd64 and arm64)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Install optional dependencies for full functionality
RUN pip install --no-cache-dir \
    neo4j>=5.0.0 \
    feedparser>=6.0.0 \
    || echo "Some optional dependencies failed to install (non-critical)"

# Copy application code
COPY . .

# Create necessary directories with proper permissions
RUN mkdir -p data/threats data/assets data/controls data/evidence data/reports data/knowledge_graphs data/config \
    && chmod -R 755 data

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Run the application
CMD ["python", "-m", "api.server"]

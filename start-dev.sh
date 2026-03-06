#!/bin/bash

echo "🚀 IoT Security Analyzer - Development Setup"
echo "=============================================="

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

echo "✅ Docker is running"

# Create environment file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file from template..."
    cp .env.example .env
    echo "✅ Created .env file (you can modify it if needed)"
fi

echo "🔧 Building and starting the application..."
echo "This may take a few minutes the first time..."

# Build and start with Docker Compose
docker-compose up --build -d

#!/bin/bash

echo "=== Quick Start for Codebase Scanner ==="
echo

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo "Docker is not running. Please start Docker first."
    echo "If you have Colima, run: colima start"
    exit 1
fi

# Create .env file from example
if [ ! -f .env ]; then
    cp .env.example .env
    echo "Created .env file from .env.example"
    echo "Please edit .env with your API keys (optional for basic testing)"
fi

# Build and start only essential services first
echo "Starting essential services..."
docker-compose up -d postgres redis

# Wait for database to be ready
echo "Waiting for database to be ready..."
sleep 10

# Start backend
echo "Starting backend..."
docker-compose up -d backend

# Wait for backend
echo "Waiting for backend to be ready..."
sleep 10

# Start frontend
echo "Starting frontend..."
docker-compose up -d frontend

echo
echo "=== Application Started ==="
echo
echo "Frontend: http://localhost:5173"
echo "Backend API: http://localhost:8000"
echo "API Docs: http://localhost:8000/docs"
echo
echo "To view logs: docker-compose logs -f"
echo "To stop: docker-compose down"
echo
echo "Next steps:"
echo "1. Open http://localhost:5173 in your browser"
echo "2. Create an account"
echo "3. Create a project with GitHub URL: https://github.com/OWASP/NodeGoat"
echo "4. Run a security scan"
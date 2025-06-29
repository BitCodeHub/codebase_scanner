#!/bin/bash

# Codebase Scanner Setup Script
# This script sets up the development environment for the codebase scanner

set -e  # Exit on any error

echo "🚀 Setting up Codebase Scanner Development Environment"
echo "======================================================"

# Check if required tools are installed
check_dependency() {
    if ! command -v $1 &> /dev/null; then
        echo "❌ $1 is not installed. Please install it first."
        exit 1
    else
        echo "✅ $1 is installed"
    fi
}

echo "📋 Checking dependencies..."
check_dependency "node"
check_dependency "npm"
check_dependency "python3"
check_dependency "pip3"
check_dependency "docker"
check_dependency "git"

# Check Node.js version
NODE_VERSION=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    echo "❌ Node.js version 18+ is required (found: $(node --version))"
    exit 1
else
    echo "✅ Node.js version $(node --version) is compatible"
fi

# Check Python version
PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1-2)
if [[ $(echo "$PYTHON_VERSION < 3.11" | bc -l) -eq 1 ]]; then
    echo "❌ Python 3.11+ is required (found: $(python3 --version))"
    exit 1
else
    echo "✅ Python $(python3 --version) is compatible"
fi

# Create environment file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "📝 Creating environment file from template..."
    cp .env.example .env
    echo "⚠️  Please update .env with your Supabase credentials"
else
    echo "✅ Environment file already exists"
fi

# Install frontend dependencies
echo "📦 Installing frontend dependencies..."
cd frontend
npm install
cd ..

# Install backend dependencies
echo "📦 Installing backend dependencies..."
cd backend
python3 -m pip install --upgrade pip
pip3 install -r requirements.txt
cd ..

# Setup pre-commit hooks (optional)
if command -v pre-commit &> /dev/null; then
    echo "🔧 Setting up pre-commit hooks..."
    pre-commit install
else
    echo "⚠️  pre-commit not found. Consider installing it for code quality checks."
fi

# Create necessary directories
echo "📁 Creating necessary directories..."
mkdir -p backend/uploads
mkdir -p backend/logs
mkdir -p frontend/dist

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo "⚠️  Docker is not running. Start Docker to use containerized development."
else
    echo "✅ Docker is running"
    
    # Build Docker images (optional)
    read -p "🐳 Build Docker images now? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "🔨 Building Docker images..."
        docker-compose build
    fi
fi

echo ""
echo "🎉 Setup completed successfully!"
echo ""
echo "📋 Next steps:"
echo "1. Update .env file with your Supabase credentials"
echo "2. Follow the Supabase setup guide in docs/SUPABASE_SETUP.md"
echo "3. Start development environment:"
echo "   npm run dev          # Start both frontend and backend"
echo "   # OR"
echo "   docker-compose up    # Start with Docker"
echo ""
echo "📚 Useful commands:"
echo "   npm run dev:frontend    # Start only frontend (port 5173)"
echo "   npm run dev:backend     # Start only backend (port 8000)"
echo "   npm run test           # Run all tests"
echo "   npm run build          # Build for production"
echo ""
echo "🌐 URLs after starting:"
echo "   Frontend: http://localhost:5173"
echo "   Backend:  http://localhost:8000"
echo "   API Docs: http://localhost:8000/docs"
echo ""
#!/bin/bash

# Script to start Docker on macOS (supports both Docker Desktop and Colima)

echo "=== Starting Docker Environment ==="
echo

# Check if using Colima
if command -v colima &> /dev/null; then
    echo "Colima detected. Starting Colima..."
    
    # Check if colima is already running
    if colima status &> /dev/null; then
        echo "Colima is already running"
    else
        # Start colima with appropriate resources
        colima start --cpu 4 --memory 8 --disk 100
        
        # Wait for colima to be ready
        echo "Waiting for Colima to start..."
        sleep 10
    fi
    
    # Verify Docker is accessible
    if docker info &> /dev/null; then
        echo "✓ Docker is now accessible via Colima"
    else
        echo "Error: Docker is still not accessible. Try:"
        echo "  colima delete"
        echo "  colima start"
        exit 1
    fi

# Check if using Docker Desktop
elif [[ -d "/Applications/Docker.app" ]]; then
    echo "Docker Desktop detected. Starting Docker Desktop..."
    
    # Check if Docker Desktop is already running
    if docker info &> /dev/null; then
        echo "Docker Desktop is already running"
    else
        # Start Docker Desktop
        open -a Docker
        
        # Wait for Docker to be ready
        echo "Waiting for Docker Desktop to start (this may take a minute)..."
        while ! docker info &> /dev/null; do
            sleep 2
            echo -n "."
        done
        echo
        echo "✓ Docker Desktop is now running"
    fi

# Check if using Rancher Desktop
elif [[ -d "/Applications/Rancher Desktop.app" ]]; then
    echo "Rancher Desktop detected. Starting Rancher Desktop..."
    
    if docker info &> /dev/null; then
        echo "Rancher Desktop is already running"
    else
        open -a "Rancher Desktop"
        
        echo "Waiting for Rancher Desktop to start..."
        while ! docker info &> /dev/null; do
            sleep 2
            echo -n "."
        done
        echo
        echo "✓ Rancher Desktop is now running"
    fi

else
    echo "No Docker runtime detected. Please install one of the following:"
    echo "1. Docker Desktop: https://www.docker.com/products/docker-desktop"
    echo "2. Colima: brew install colima"
    echo "3. Rancher Desktop: https://rancherdesktop.io/"
    exit 1
fi

# Verify Docker is working
echo
echo "Verifying Docker installation..."
docker --version
docker-compose --version

echo
echo "✓ Docker is ready to use!"
echo
echo "Now you can run:"
echo "  cd /Users/jimmylam/Documents/security"
echo "  ./test_app.sh"
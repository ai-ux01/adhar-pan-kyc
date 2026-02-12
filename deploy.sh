#!/bin/bash

# Production Deployment Script for KYC Aadhaar App
# Usage: ./deploy.sh [frontend|backend|all]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Node.js and npm are installed
check_dependencies() {
    print_status "Checking dependencies..."
    
    if ! command -v node &> /dev/null; then
        print_error "Node.js is not installed. Please install Node.js 16+ first."
        exit 1
    fi
    
    if ! command -v npm &> /dev/null; then
        print_error "npm is not installed. Please install npm first."
        exit 1
    fi
    
    print_status "Dependencies check passed ✓"
}

# Deploy frontend
deploy_frontend() {
    print_status "Deploying frontend..."
    
    cd frontend
    
    # Install dependencies
    print_status "Installing frontend dependencies..."
    npm ci --only=production
    
    # Build for production
    print_status "Building frontend for production..."
    npm run build:prod
    
    # Create production build directory
    if [ ! -d "../dist/frontend" ]; then
        mkdir -p ../dist/frontend
    fi
    
    # Copy build files
    cp -r build/* ../dist/frontend/
    
    print_status "Frontend deployment completed ✓"
    cd ..
}

# Deploy backend
deploy_backend() {
    print_status "Deploying backend..."
    
    cd backend
    
    # Install dependencies
    print_status "Installing backend dependencies..."
    npm ci --only=production
    
    # Create production directory
    if [ ! -d "../dist/backend" ]; then
        mkdir -p ../dist/backend
    fi
    
    # Copy backend files
    cp -r src ../dist/backend/
    cp -r uploads ../dist/backend/ 2>/dev/null || true
    cp -r logs ../dist/backend/ 2>/dev/null || true
    cp package.json ../dist/backend/
    cp ecosystem.config.js ../dist/backend/
    
    # Create production environment file
    if [ ! -f "../dist/backend/.env" ]; then
        print_warning "Creating production .env file from template..."
        cp env.example ../dist/backend/.env
        print_warning "Please update the .env file with production values!"
    fi
    
    print_status "Backend deployment completed ✓"
    cd ..
}

# Main deployment function
main() {
    print_status "Starting production deployment..."
    
    check_dependencies
    
    case "${1:-all}" in
        "frontend")
            deploy_frontend
            ;;
        "backend")
            deploy_backend
            ;;
        "all")
            deploy_frontend
            deploy_backend
            ;;
        *)
            print_error "Invalid option. Use: frontend, backend, or all"
            exit 1
            ;;
    esac
    
    print_status "Deployment completed successfully! 🚀"
    print_warning "Next steps:"
    print_warning "1. Update production environment variables"
    print_warning "2. Configure your web server (nginx/apache)"
    print_warning "3. Set up SSL certificates"
    print_warning "4. Configure PM2 for backend: cd dist/backend && npm run pm2:start"
}

# Run main function
main "$@"



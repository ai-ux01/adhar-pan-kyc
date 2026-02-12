#!/bin/bash

# Railway start script
echo "🚀 Starting KYC Aadhaar Backend on Railway..."

# Navigate to backend directory
cd backend

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
fi

# Start the application
echo "🎯 Starting Node.js server..."
npm start

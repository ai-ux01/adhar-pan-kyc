#!/bin/bash

# Script to deploy backend to AWS Amplify (Lambda + API Gateway)
# This creates a separate Amplify project for the backend

echo "🚀 Deploying Backend to AWS Amplify"
echo ""

# Check if Amplify CLI is installed
if ! command -v amplify &> /dev/null; then
    echo "❌ AWS Amplify CLI is not installed."
    echo "   Install it with: npm install -g @aws-amplify/cli"
    exit 1
fi

echo "✅ AWS Amplify CLI found"
echo ""

# Check if AWS CLI is configured
if ! aws sts get-caller-identity &> /dev/null; then
    echo "⚠️  AWS CLI is not configured or credentials are invalid."
    echo "   Run: aws configure"
    exit 1
fi

echo "✅ AWS CLI configured"
echo ""

# Check if already initialized
if [ -d "amplify" ] && [ -f "amplify/.config/project-config.json" ]; then
    echo "⚠️  Amplify backend is already initialized."
    read -p "Do you want to continue with existing setup? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    echo "📦 Initializing Amplify backend project..."
    echo ""
    echo "Please follow the prompts:"
    echo "  - Project name: kyc-backend (or your choice)"
    echo "  - Environment: dev"
    echo "  - Default editor: (your choice)"
    echo "  - Type of app: javascript"
    echo "  - Framework: none"
    echo "  - Source directory: ."
    echo "  - Distribution directory: (leave empty)"
    echo "  - Build command: (leave empty)"
    echo "  - Start command: (leave empty)"
    echo "  - AWS profile: (select your profile)"
    echo ""
    
    amplify init
fi

echo ""
echo "📦 Setting up Lambda function with backend code..."
echo ""

# Create Lambda function directory structure if it doesn't exist
LAMBDA_DIR="amplify/backend/function/expressBackend/src"
mkdir -p "$LAMBDA_DIR"

# Copy backend code to Lambda function
if [ -d "backend/src" ]; then
    echo "Copying backend source code to Lambda function..."
    mkdir -p "$LAMBDA_DIR/backend/src"
    cp -r backend/src/* "$LAMBDA_DIR/backend/src/"
    
    # Copy package.json if it exists
    if [ -f "backend/package.json" ]; then
        cp backend/package.json "$LAMBDA_DIR/backend/"
    fi
    
    echo "✅ Backend code copied"
else
    echo "⚠️  Backend source directory not found. Make sure backend/src exists."
fi

# Install Lambda wrapper dependencies
echo ""
echo "📦 Installing Lambda wrapper dependencies..."
cd "$LAMBDA_DIR"
if [ ! -f "package.json" ]; then
    npm init -y
fi
npm install serverless-http --save
cd ../../../../..

echo ""
echo "✅ Dependencies installed"
echo ""

# Check if API is already added
if [ ! -d "amplify/backend/api" ]; then
    echo "📡 Adding API Gateway + Lambda function..."
    echo ""
    echo "Please follow the prompts:"
    echo "  - Select: REST"
    echo "  - Resource name: backendapi"
    echo "  - Path: /api"
    echo "  - Lambda function: Create new function"
    echo "    - Function name: expressBackend"
    echo "    - Runtime: Node.js 18.x"
    echo "    - Template: Hello World"
    echo "    - Advanced settings: Yes"
    echo "      - Environment variables: Add your backend env vars"
    echo ""
    
    amplify add api
else
    echo "✅ API Gateway already configured"
fi

echo ""
echo "⚙️  Configuring environment variables..."
echo ""
echo "You can set environment variables now or later with:"
echo "  amplify update function"
echo ""
read -p "Do you want to configure environment variables now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    amplify update function
fi

echo ""
echo "🚀 Deploying backend to AWS..."
echo ""
echo "This will:"
echo "  - Create/update Lambda function"
echo "  - Create/update API Gateway"
echo "  - Deploy your backend"
echo ""
read -p "Continue with deployment? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    amplify push
    
    echo ""
    echo "✅ Backend deployed!"
    echo ""
    echo "📝 Next steps:"
    echo "  1. Copy the API Gateway URL from the output above"
    echo "  2. Deploy frontend to separate Amplify app"
    echo "  3. Set REACT_APP_API_URL in frontend to the API Gateway URL"
    echo "  4. Update CORS on API Gateway to allow frontend domain"
    echo ""
    echo "See SEPARATE_AMPLIFY_DEPLOYMENT.md for detailed instructions"
else
    echo "Deployment cancelled. Run 'amplify push' when ready."
fi


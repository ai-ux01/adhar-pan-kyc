#!/bin/bash

# Setup script for AWS Amplify Backend Integration
# This script helps set up the Amplify backend configuration

echo "🚀 Setting up AWS Amplify Backend Integration"
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
    echo "⚠️  Amplify is already initialized."
    read -p "Do you want to continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "📦 Installing serverless-http for Lambda function..."
cd amplify/backend/function/expressBackend/src
if [ ! -f "package.json" ]; then
    echo "❌ package.json not found. Creating it..."
    npm init -y
fi
npm install serverless-http --save
cd ../../../../..

echo ""
echo "✅ Dependencies installed"
echo ""

echo "📝 Next steps:"
echo ""
echo "1. Initialize Amplify (if not done):"
echo "   amplify init"
echo ""
echo "2. Add API Gateway + Lambda function:"
echo "   amplify add api"
echo "   - Select: REST"
echo "   - Resource name: backendapi"
echo "   - Path: /api"
echo "   - Lambda function: Use existing function 'expressBackend'"
echo ""
echo "3. Configure environment variables:"
echo "   amplify update function"
echo "   - Select: expressBackend"
echo "   - Add your environment variables (MONGODB_URI, JWT_SECRET, etc.)"
echo ""
echo "4. Deploy backend:"
echo "   amplify push"
echo ""
echo "5. Update frontend environment variables in Amplify Console:"
echo "   REACT_APP_API_URL=<your-api-gateway-url>/api"
echo ""
echo "📚 For detailed instructions, see: AMPLIFY_BACKEND_SETUP.md"
echo ""


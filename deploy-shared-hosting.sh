#!/bin/bash

# Shared Hosting Deployment Script for KYC Aadhaar App
# Usage: ./deploy-shared-hosting.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

print_header() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check if Node.js and npm are installed
check_dependencies() {
    print_header "Checking dependencies..."
    
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

# Build frontend for shared hosting
build_frontend() {
    print_header "Building frontend for shared hosting..."
    
    cd frontend
    
    # Install dependencies
    print_status "Installing frontend dependencies..."
    npm ci --only=production
    
    # Build for production
    print_status "Building frontend for production..."
    npm run build
    
    print_status "Frontend build completed ✓"
    cd ..
}

# Prepare backend for shared hosting
prepare_backend() {
    print_header "Preparing backend for shared hosting..."
    
    cd backend
    
    # Install dependencies
    print_status "Installing backend dependencies..."
    npm ci --only=production
    
    print_status "Backend preparation completed ✓"
    cd ..
}

# Create shared hosting deployment package
create_deployment_package() {
    print_header "Creating shared hosting deployment package..."
    
    # Create deployment directory
    if [ -d "shared-hosting-deploy" ]; then
        rm -rf shared-hosting-deploy
    fi
    
    mkdir -p shared-hosting-deploy/pankyc
    
    # Copy frontend build
    print_status "Copying frontend build..."
    cp -r frontend/build/* shared-hosting-deploy/pankyc/
    
    # Copy backend files
    print_status "Copying backend files..."
    mkdir -p shared-hosting-deploy/pankyc/api
    cp -r backend/src shared-hosting-deploy/pankyc/api/
    cp -r backend/uploads shared-hosting-deploy/pankyc/api/ 2>/dev/null || true
    cp -r backend/logs shared-hosting-deploy/pankyc/api/ 2>/dev/null || true
    cp backend/shared-hosting-server.js shared-hosting-deploy/pankyc/api/
    cp backend/package.json shared-hosting-deploy/pankyc/api/
    cp backend/production.env shared-hosting-deploy/pankyc/api/.env
    
    # Copy configuration files
    print_status "Copying configuration files..."
    cp .htaccess shared-hosting-deploy/pankyc/
    
    # Create uploads directory if it doesn't exist
    mkdir -p shared-hosting-deploy/pankyc/api/uploads
    mkdir -p shared-hosting-deploy/pankyc/api/logs
    
    print_status "Deployment package created ✓"
}

# Create deployment instructions
create_instructions() {
    print_header "Creating deployment instructions..."
    
    cat > shared-hosting-deploy/DEPLOYMENT_INSTRUCTIONS.txt << EOF
🚀 KYC Aadhaar App - Shared Hosting Deployment Instructions

📁 Directory Structure:
shared-hosting-deploy/
└── pankyc/                    # Upload this entire folder to your hosting
    ├── index.html            # Frontend files
    ├── static/               # Frontend assets
    ├── api/                  # Backend API
    │   ├── shared-hosting-server.js
    │   ├── package.json
    │   ├── .env
    │   ├── src/
    │   ├── uploads/
    │   └── logs/
    └── .htaccess             # Apache configuration

📋 Deployment Steps:

1. 📤 Upload Files:
   - Upload the entire 'pankyc' folder to your hosting's public_html directory
   - Final path should be: public_html/pankyc/

2. 🔧 Configure Environment:
   - Edit public_html/pankyc/api/.env with your production values
   - Update MongoDB connection string
   - Set strong JWT secrets
   - Configure email settings

3. 🗄️ Database Setup:
   - Option A: Use your hosting provider's MongoDB
   - Option B: Use MongoDB Atlas (free tier)
   - Option C: Use MLab (free tier)

4. 🚀 Start Application:
   - If your hosting supports Node.js:
     * SSH into your hosting
     * cd public_html/pankyc/api
     * npm install
     * npm start
   
   - If using cPanel Node.js Selector:
     * Go to cPanel → Node.js Selector
     * Create new application
     * Set path to: public_html/pankyc/api
     * Set startup file to: shared-hosting-server.js
     * Start the application

5. ✅ Test Deployment:
   - Frontend: https://www.ass.com/pankyc/
   - API Health: https://www.ass.com/pankyc/api/health
   - API Login: https://www.ass.com/pankyc/api/auth/login

🔧 Environment Variables to Update in .env:
- MONGODB_URI: Your MongoDB connection string
- JWT_SECRET: Strong secret key (32+ characters)
- ENCRYPTION_KEY: 32-character encryption key
- SMTP_HOST, SMTP_USER, SMTP_PASS: Email configuration
- PAN_KYC_API_URL, AADHAAR_PAN_API_URL: External API URLs
- SANDBOX_API_KEY, SANDBOX_API_SECRET: API credentials

🛡️ Security Checklist:
- [ ] Strong passwords and secrets in .env
- [ ] SSL certificate installed
- [ ] File permissions set correctly (644 for files, 755 for directories)
- [ ] .env file not accessible via web
- [ ] Database access restricted
- [ ] Rate limiting enabled

📞 Support:
- Check logs in public_html/pankyc/api/logs/
- Verify Node.js version compatibility
- Ensure all dependencies are installed
- Test API endpoints individually

🎉 Your KYC Aadhaar App will be accessible at:
- https://www.ass.com/pankyc/
EOF

    print_status "Deployment instructions created ✓"
}

# Create package.json for shared hosting
create_package_json() {
    print_header "Creating package.json for shared hosting..."
    
    cat > shared-hosting-deploy/pankyc/api/package.json << EOF
{
  "name": "kyc-aadhaar-shared-hosting",
  "version": "1.0.0",
  "description": "KYC Aadhaar App for Shared Hosting",
  "main": "shared-hosting-server.js",
  "scripts": {
    "start": "node shared-hosting-server.js",
    "dev": "nodemon shared-hosting-server.js"
  },
  "dependencies": {
    "express": "^4.21.2",
    "cors": "^2.8.5",
    "helmet": "^7.0.0",
    "express-rate-limit": "^6.10.0",
    "mongoose": "^7.5.0",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "dotenv": "^16.3.1",
    "multer": "^1.4.5-lts.1",
    "winston": "^3.10.0",
    "xlsx": "^0.18.5",
    "axios": "^1.11.0",
    "crypto-js": "^4.1.1",
    "express-validator": "^7.0.1",
    "morgan": "^1.10.0",
    "nodemailer": "^6.9.4"
  },
  "engines": {
    "node": ">=16.0.0",
    "npm": ">=8.0.0"
  }
}
EOF

    print_status "Package.json created ✓"
}

# Main deployment function
main() {
    print_header "Starting shared hosting deployment preparation..."
    
    check_dependencies
    build_frontend
    prepare_backend
    create_deployment_package
    create_package_json
    create_instructions
    
    print_status "🎉 Shared hosting deployment package ready!"
    print_warning "Next steps:"
    print_warning "1. Upload 'shared-hosting-deploy/pankyc/' folder to your hosting"
    print_warning "2. Configure environment variables in .env file"
    print_warning "3. Set up database connection"
    print_warning "4. Start the Node.js application"
    print_warning "5. Test at https://www.ass.com/pankyc/"
    
    print_status "📁 Deployment package location: shared-hosting-deploy/"
    print_status "📋 Instructions: shared-hosting-deploy/DEPLOYMENT_INSTRUCTIONS.txt"
}

# Run main function
main "$@"



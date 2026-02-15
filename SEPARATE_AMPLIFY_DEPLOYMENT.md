# Separate Amplify Deployment Guide
## Frontend on One Amplify App | Backend on Another Amplify Project

This guide explains how to deploy the frontend and backend as separate Amplify applications.

## Architecture Overview

```
┌─────────────────────────────────┐
│   Amplify App #1 (Frontend)      │
│   - React App Hosting            │
│   - URL: main.xxxxx.amplifyapp.com│
└─────────────────────────────────┘
              │
              │ API Calls
              ▼
┌─────────────────────────────────┐
│   Amplify Project #2 (Backend)   │
│   - Lambda Functions             │
│   - API Gateway                  │
│   - URL: xxxxx.execute-api...    │
└─────────────────────────────────┘
```

## Part 1: Deploy Backend to Amplify (Lambda + API Gateway)

### Step 1: Create Backend Amplify Project

```bash
# Navigate to project root
cd /path/to/adhar-pan-kyc-main

# Initialize Amplify for backend (separate project)
amplify init

# Follow prompts:
# - Enter a name for the project: kyc-backend
# - Initialize the project with the above settings? Yes
# - Select authentication method: AWS profile
# - Select region: us-east-1 (or your preferred region)
# - This will create a separate Amplify project for backend
```

### Step 2: Add API Gateway + Lambda

```bash
# Add REST API
amplify add api

# Follow prompts:
# - Select: REST
# - Resource name: backendapi
# - Path: /api
# - Lambda function: Create new function
#   - Function name: expressBackend
#   - Runtime: Node.js 18.x
#   - Template: Hello World
#   - Advanced settings: Yes
#     - Environment variables: Add your backend env vars
```

### Step 3: Configure Lambda Function

The Lambda function wrapper is already created at:
- `amplify/backend/function/expressBackend/src/index.js`

You need to bundle your backend code with the Lambda function:

```bash
# Option A: Copy backend to Lambda (for small apps)
cd amplify/backend/function/expressBackend/src
mkdir -p backend
cp -r ../../../../../backend/src backend/
cp ../../../../../backend/package.json backend/

# Install backend dependencies
cd backend
npm install --production
cd ..

# Install Lambda wrapper dependencies
npm install serverless-http
```

### Step 4: Update Lambda Handler

Edit `amplify/backend/function/expressBackend/src/index.js`:

```javascript
const serverless = require('serverless-http');
const app = require('./backend/src/server');

module.exports.handler = serverless(app, {
  binary: [
    'image/*',
    'application/pdf',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  ]
});
```

### Step 5: Set Environment Variables

```bash
amplify update function

# Select: expressBackend
# Select: Environment variables
# Add:
#   - MONGODB_URI: mongodb://...
#   - JWT_SECRET: your-secret
#   - ENCRYPTION_KEY: your-key
#   - SANDBOX_API_KEY: your-key
#   - SANDBOX_API_SECRET: your-secret
#   - NODE_ENV: production
#   - (all other backend env vars)
```

### Step 6: Deploy Backend

```bash
# Push backend to AWS
amplify push

# This will:
# - Create Lambda function
# - Create API Gateway
# - Deploy your backend
# - Output API Gateway URL
```

**Save the API Gateway URL** - you'll need it for the frontend!

Example output:
```
REST API endpoint: https://xxxxx.execute-api.us-east-1.amazonaws.com/dev
```

### Step 7: Configure CORS for Frontend

After deployment, update API Gateway CORS settings to allow your frontend domain:

```bash
# In AWS Console → API Gateway → Your API → Actions → Enable CORS
# Or use AWS CLI:
aws apigatewayv2 update-api --api-id <api-id> --cors-configuration '{
  "AllowOrigins": ["https://main.xxxxx.amplifyapp.com"],
  "AllowMethods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  "AllowHeaders": ["Content-Type", "Authorization"],
  "AllowCredentials": true
}'
```

## Part 2: Deploy Frontend to Separate Amplify App

### Step 1: Create Frontend Amplify App (in AWS Console)

1. Go to [AWS Amplify Console](https://console.aws.amazon.com/amplify/)
2. Click **"New app"** → **"Host web app"**
3. Connect your GitHub/GitLab/Bitbucket repository
4. Select branch: `main`
5. **App name**: `kyc-frontend` (or your preferred name)

### Step 2: Configure Build Settings

The `amplify.yml` file is already configured. Amplify will auto-detect it.

If needed, verify the build settings:
- **Base directory**: (leave empty, root)
- **Build command**: `cd frontend && npm ci && npm run build`
- **Output directory**: `frontend/build`

### Step 3: Set Environment Variables

In Amplify Console → **App settings** → **Environment variables**, add:

```bash
# Backend API URL (from Step 6 of Part 1)
REACT_APP_API_URL=https://xxxxx.execute-api.us-east-1.amazonaws.com/dev/api

# Other variables
REACT_APP_ENVIRONMENT=production
NODE_ENV=production
```

**Important**: Use the API Gateway URL from your backend deployment!

### Step 4: Deploy Frontend

1. Click **"Save and deploy"**
2. Wait for deployment to complete
3. Your frontend will be available at: `https://main.xxxxx.amplifyapp.com`

## Part 3: Connect Frontend to Backend

### Update CORS on Backend API Gateway

After frontend is deployed, get the frontend URL and update backend CORS:

```bash
# Get your frontend URL from Amplify Console
FRONTEND_URL=https://main.xxxxx.amplifyapp.com

# Update API Gateway CORS (via AWS Console or CLI)
# Allow origin: FRONTEND_URL
```

### Test the Connection

1. Open your frontend URL
2. Open browser DevTools → Network tab
3. Try logging in or making an API call
4. Verify requests go to: `https://xxxxx.execute-api.us-east-1.amazonaws.com/dev/api`

## Managing Two Separate Amplify Projects

### Backend Project (Lambda + API Gateway)

```bash
# Work with backend Amplify project
cd /path/to/adhar-pan-kyc-main
amplify status          # Check backend status
amplify push            # Deploy backend changes
amplify pull            # Pull backend changes
amplify delete          # Delete backend (careful!)
```

### Frontend App (Amplify Hosting)

- Managed via AWS Amplify Console (web UI)
- Or use Amplify CLI with separate project:
  ```bash
  # In a different directory or branch
  amplify init --appId <frontend-app-id>
  ```

## Directory Structure

```
adhar-pan-kyc-main/
├── amplify/                    # Backend Amplify project
│   ├── backend/
│   │   ├── api/backendapi/     # API Gateway
│   │   └── function/expressBackend/  # Lambda
│   └── team-provider-info.json
├── frontend/                   # Frontend code
├── backend/                    # Backend source code
├── amplify.yml                 # Frontend build config
└── .amplifyrc                  # Backend project config
```

## Environment Variables Summary

### Backend Lambda Function (via `amplify update function`)
- `MONGODB_URI`
- `JWT_SECRET`
- `ENCRYPTION_KEY`
- `SANDBOX_API_KEY`
- `SANDBOX_API_SECRET`
- `NODE_ENV=production`
- All other backend env vars

### Frontend Amplify App (via Console)
- `REACT_APP_API_URL` ← **Backend API Gateway URL**
- `REACT_APP_ENVIRONMENT=production`
- `NODE_ENV=production`

## Troubleshooting

### Frontend Can't Connect to Backend

1. **Check API URL**: Verify `REACT_APP_API_URL` in frontend env vars
2. **Check CORS**: Ensure API Gateway allows frontend origin
3. **Check Lambda**: Verify Lambda function is deployed and working
4. **Check API Gateway**: Test API Gateway endpoint directly

```bash
# Test backend endpoint
curl https://xxxxx.execute-api.us-east-1.amazonaws.com/dev/api/health
```

### Backend Not Deploying

1. **Check Amplify CLI**: `amplify --version`
2. **Check AWS Credentials**: `aws sts get-caller-identity`
3. **Check Lambda Size**: Large dependencies may need Lambda Layers
4. **Check Logs**: `amplify logs function expressBackend`

### CORS Errors

1. Update API Gateway CORS settings
2. Verify frontend URL is in allowed origins
3. Check preflight OPTIONS requests are handled

## Cost Considerations

### Backend (Lambda + API Gateway)
- **Lambda**: Pay per request (~$0.20 per 1M requests)
- **API Gateway**: Pay per API call (~$3.50 per 1M requests)
- **Free tier**: 1M Lambda requests/month, 1M API Gateway calls/month

### Frontend (Amplify Hosting)
- **Free tier**: 15 GB storage, 5 GB bandwidth/month
- **Paid**: $0.15/GB storage, $0.15/GB bandwidth

## Quick Reference Commands

### Backend
```bash
amplify init              # Initialize backend project
amplify add api           # Add API Gateway + Lambda
amplify update function   # Update Lambda config
amplify push              # Deploy backend
amplify status            # Check status
```

### Frontend
- Managed via AWS Amplify Console
- Or use: `amplify add hosting` (if using CLI)

## Next Steps

1. ✅ Deploy backend: `amplify push`
2. ✅ Get API Gateway URL
3. ✅ Deploy frontend: AWS Amplify Console
4. ✅ Set `REACT_APP_API_URL` in frontend
5. ✅ Update CORS on API Gateway
6. ✅ Test connection

## Support

- Backend issues: Check `amplify/backend/` directory
- Frontend issues: Check AWS Amplify Console logs
- API Gateway: Check CloudWatch logs for Lambda function


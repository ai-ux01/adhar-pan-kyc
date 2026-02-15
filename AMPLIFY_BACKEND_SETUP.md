# AWS Amplify Backend Integration Guide

This guide explains how to set up and deploy the backend to AWS Amplify.

## Overview

The backend integration includes:
- **Lambda Function**: Express.js backend wrapped for AWS Lambda
- **API Gateway**: REST API endpoints for backend routes
- **Cognito**: User authentication (optional, can use existing JWT)
- **DynamoDB**: Alternative storage option (optional, can keep MongoDB)

## Prerequisites

1. AWS Account with appropriate permissions
2. AWS Amplify CLI installed: `npm install -g @aws-amplify/cli`
3. AWS CLI configured: `aws configure`

## Setup Steps

### 1. Initialize Amplify Backend

```bash
# Navigate to project root
cd /path/to/adhar-pan-kyc-main

# Initialize Amplify (if not already done)
amplify init

# Follow the prompts:
# - Enter a name for the project: kycapp
# - Initialize the project with the above settings? Yes
# - Select authentication method: AWS profile
# - Select region: us-east-1 (or your preferred region)
```

### 2. Add Backend Services

#### Option A: Use Lambda Function for Express Backend

```bash
# Add Lambda function
amplify add function

# Follow prompts:
# - Function name: expressBackend
# - Runtime: Node.js 18.x
# - Template: Hello World
# - Advanced settings: Yes
#   - Environment variables: Add your backend env vars
#   - Lambda layers: None
```

#### Option B: Use API Gateway + Lambda (Recommended)

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
```

### 3. Configure Lambda Function

The Lambda function wrapper is located at:
- `amplify/backend/function/expressBackend/src/index.js`

This wraps your Express app using `serverless-http`. Make sure to:

1. Install dependencies in the Lambda function:
```bash
cd amplify/backend/function/expressBackend
npm install serverless-http
```

2. Copy backend dependencies (or use Lambda Layers):
```bash
# Option 1: Copy node_modules (not recommended for large apps)
# Option 2: Use Lambda Layers (recommended)
amplify add function
# Select: Lambda layer
# Follow prompts to create a layer with your backend dependencies
```

### 4. Set Environment Variables

Add environment variables for your Lambda function:

```bash
amplify update function

# Select: expressBackend
# Select: Environment variables
# Add variables:
# - MONGODB_URI: Your MongoDB connection string
# - JWT_SECRET: Your JWT secret
# - ENCRYPTION_KEY: Your encryption key
# - SANDBOX_API_KEY: Your Sandbox API key
# - SANDBOX_API_SECRET: Your Sandbox API secret
# - etc.
```

Or manually edit: `amplify/backend/function/expressBackend/cli-inputs.json`

### 5. Deploy Backend

```bash
# Push backend to AWS
amplify push

# This will:
# - Create Lambda function
# - Create API Gateway
# - Set up IAM roles
# - Deploy your backend
```

### 6. Get API Endpoint

After deployment, Amplify will provide:
- API Gateway endpoint URL
- Lambda function ARN

Update your frontend environment variables:

```bash
# In AWS Amplify Console → Environment variables
REACT_APP_API_URL=https://xxxxx.execute-api.us-east-1.amazonaws.com/dev/api
```

## Alternative: Keep Existing Backend on Render

If you prefer to keep your backend on Render and only use Amplify for frontend hosting:

1. **No backend changes needed**
2. **Update CORS** in your Render backend to allow Amplify domain:
   ```bash
   ALLOWED_ORIGINS=https://main.xxxxx.amplifyapp.com
   ```
3. **Set frontend environment variable** in Amplify Console:
   ```bash
   REACT_APP_API_URL=https://adhar-pan-kyc-1.onrender.com/api
   ```

## Migration Strategy

### Option 1: Gradual Migration
1. Keep backend on Render initially
2. Set up Amplify backend in parallel
3. Test Amplify backend endpoints
4. Switch frontend to use Amplify backend
5. Decommission Render backend

### Option 2: Full Migration
1. Set up Amplify backend
2. Migrate data from MongoDB to DynamoDB (if switching)
3. Update all environment variables
4. Deploy and test
5. Switch DNS/endpoints

## Database Options

### Keep MongoDB (Recommended for existing data)
- Use MongoDB Atlas (cloud-hosted)
- Update `MONGODB_URI` in Lambda environment variables
- No data migration needed

### Switch to DynamoDB
- Use Amplify storage: `amplify add storage`
- Migrate data from MongoDB
- Update backend code to use DynamoDB SDK

## Authentication Options

### Keep JWT (Current)
- No changes needed
- Continue using existing JWT authentication

### Switch to Cognito
- Use Amplify Auth: `amplify add auth`
- Update frontend to use Amplify Auth SDK
- Migrate users to Cognito User Pool

## Troubleshooting

### Lambda Function Timeout
- Increase timeout in `cli-inputs.json`: `"timeout": 60`
- Optimize Express app startup

### Cold Start Issues
- Use Lambda Provisioned Concurrency
- Optimize dependencies (remove unused packages)
- Use Lambda Layers for shared dependencies

### API Gateway CORS Issues
- Configure CORS in API Gateway console
- Or handle in Express app (already configured)

### Environment Variables Not Working
- Ensure variables are set in `cli-inputs.json`
- Redeploy after changes: `amplify push`

## Cost Considerations

- **Lambda**: Pay per request (very low for small apps)
- **API Gateway**: Pay per API call
- **DynamoDB**: Pay per request (if using)
- **Cognito**: Free tier available

Compare with Render costs to decide which is better for your use case.

## Next Steps

1. Choose your migration strategy
2. Set up Amplify backend services
3. Test endpoints
4. Update frontend configuration
5. Deploy and monitor

For detailed instructions, see:
- [AWS Amplify CLI Documentation](https://docs.amplify.aws/cli/)
- [Serverless Express Guide](https://github.com/vendia/serverless-express)


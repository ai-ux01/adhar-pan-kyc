# AWS Amplify Backend Integration - Summary

## What Was Added

### 1. Amplify Backend Configuration Files
- ✅ `amplify/backend/api/backendapi/` - API Gateway configuration
- ✅ `amplify/backend/function/expressBackend/` - Lambda function for Express backend
- ✅ `amplify/backend/storage/kycdata/` - DynamoDB storage (optional)
- ✅ `amplify/backend/auth/kycapp/` - Cognito authentication (optional)
- ✅ `amplify/.config/project-config.json` - Amplify project configuration
- ✅ `.amplifyrc` - Amplify runtime configuration

### 2. Lambda Function Wrapper
- ✅ `amplify/backend/function/expressBackend/src/index.js` - Serverless wrapper for Express app
- ✅ Uses `serverless-http` to convert API Gateway events to Express requests

### 3. Documentation
- ✅ `AMPLIFY_BACKEND_SETUP.md` - Complete setup guide
- ✅ `AMPLIFY_QUICK_START.md` - Updated with backend options
- ✅ Setup script: `setup-amplify-backend.sh`

### 4. Build Configuration
- ✅ Updated `amplify.yml` to include backend build steps
- ✅ Updated `.gitignore` to exclude Amplify-specific files

## Integration Options

### Option 1: Keep Backend on Render (Current Setup)
**Status**: ✅ Already working

- Frontend on Amplify
- Backend on Render
- Just update CORS on Render to allow Amplify domain

**Pros:**
- No changes needed
- Backend already working
- Quick setup

**Cons:**
- Two separate services
- Render free tier limitations

### Option 2: Deploy Backend to AWS Amplify
**Status**: ✅ Configuration ready, needs deployment

- Frontend on Amplify
- Backend on AWS Lambda + API Gateway
- Full AWS integration

**Pros:**
- Everything in one AWS account
- Better scalability
- AWS free tier available
- Integrated monitoring

**Cons:**
- Requires AWS setup
- Need to migrate/deploy backend
- Lambda cold starts possible

## Next Steps

### To Use Existing Backend (Option 1):
1. ✅ Already done - just update CORS on Render
2. Set `REACT_APP_API_URL` in Amplify Console to Render URL

### To Deploy Backend to AWS (Option 2):
1. Run setup script: `./setup-amplify-backend.sh`
2. Initialize Amplify: `amplify init`
3. Add API: `amplify add api` (select REST)
4. Configure environment variables
5. Deploy: `amplify push`
6. Update frontend `REACT_APP_API_URL` to API Gateway URL

## File Structure

```
amplify/
├── backend/
│   ├── api/
│   │   └── backendapi/          # API Gateway config
│   ├── function/
│   │   └── expressBackend/      # Lambda function
│   ├── storage/
│   │   └── kycdata/             # DynamoDB (optional)
│   └── auth/
│       └── kycapp/              # Cognito (optional)
├── .config/
│   └── project-config.json     # Project config
└── team-provider-info.json     # Environment info
```

## Important Notes

1. **Lambda Function Path**: The Lambda function currently references the backend at `../../../../../backend/src/server`. You may need to:
   - Bundle the backend with the Lambda function, OR
   - Use Lambda Layers for dependencies, OR
   - Keep backend external (Option 1)

2. **Environment Variables**: Set these in Lambda function:
   - `MONGODB_URI`
   - `JWT_SECRET`
   - `ENCRYPTION_KEY`
   - `SANDBOX_API_KEY`
   - `SANDBOX_API_SECRET`
   - And all other backend env vars

3. **Database**: You can:
   - Keep MongoDB Atlas (recommended for existing data)
   - Switch to DynamoDB (requires data migration)

4. **Authentication**: You can:
   - Keep JWT (current setup)
   - Switch to Cognito (requires user migration)

## Testing

After deployment, test the backend:

```bash
# Get API endpoint
amplify status

# Test health endpoint
curl https://xxxxx.execute-api.us-east-1.amazonaws.com/dev/api/health
```

## Troubleshooting

See `AMPLIFY_BACKEND_SETUP.md` for detailed troubleshooting guide.

## Support

- [AWS Amplify Documentation](https://docs.amplify.aws/)
- [Serverless Express Guide](https://github.com/vendia/serverless-express)
- Project docs: `AMPLIFY_BACKEND_SETUP.md`


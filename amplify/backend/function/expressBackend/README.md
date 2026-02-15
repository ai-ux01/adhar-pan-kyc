# Express Backend Lambda Function

This Lambda function wraps the Express.js backend to work with AWS API Gateway.

## Setup

### Option 1: Bundle Backend with Lambda (Recommended for small apps)

1. Copy backend code to Lambda function:
```bash
# From project root
cp -r backend/src amplify/backend/function/expressBackend/src/backend
cp backend/package.json amplify/backend/function/expressBackend/src/backend/
```

2. Install backend dependencies:
```bash
cd amplify/backend/function/expressBackend/src/backend
npm install --production
```

3. Update `index.js` to use bundled backend:
```javascript
const app = require('./backend/src/server');
```

### Option 2: Use Lambda Layers (Recommended for large apps)

1. Create a Lambda Layer with backend dependencies:
```bash
amplify add function
# Select: Lambda layer
# Name: backendDependencies
```

2. Package backend dependencies:
```bash
mkdir -p layer/nodejs
cd layer/nodejs
npm install --production <your-backend-dependencies>
```

3. Reference the layer in `cli-inputs.json`:
```json
{
  "lambdaLayers": ["backendDependencies"]
}
```

### Option 3: Use External Backend (Current Setup)

Keep backend on Render/Vercel and use Amplify only for frontend:
- No Lambda function needed
- Update frontend to point to external backend URL
- Configure CORS on external backend

## Environment Variables

Set these in `cli-inputs.json` or via Amplify CLI:

```bash
amplify update function
# Select: expressBackend
# Select: Environment variables
```

Required variables:
- `MONGODB_URI`: MongoDB connection string
- `JWT_SECRET`: JWT signing secret
- `ENCRYPTION_KEY`: Data encryption key
- `SANDBOX_API_KEY`: Sandbox API key
- `SANDBOX_API_SECRET`: Sandbox API secret
- `NODE_ENV`: production

## Deployment

```bash
amplify push
```

## Testing

After deployment, test the Lambda function:

```bash
# Get API Gateway endpoint
amplify status

# Test health endpoint
curl https://xxxxx.execute-api.us-east-1.amazonaws.com/dev/api/health
```

## Troubleshooting

### Cold Start Issues
- Increase memory allocation in `cli-inputs.json`
- Use Lambda Provisioned Concurrency
- Optimize dependencies

### Timeout Issues
- Increase timeout in `cli-inputs.json`: `"timeout": 60`
- Optimize Express app startup time

### Module Not Found Errors
- Ensure all dependencies are in `package.json`
- Check Lambda Layer configuration
- Verify file paths in `index.js`


# How to Check Environment Variables on AWS Amplify

## Step-by-Step Guide

### Method 1: Via AWS Amplify Console (Web UI)

1. **Log in to AWS Amplify Console**
   - Go to [AWS Amplify Console](https://console.aws.amazon.com/amplify/)
   - Sign in with your AWS account credentials

2. **Select Your App**
   - In the Amplify Console dashboard, find and click on your app name
   - This will take you to the app's main page

3. **Navigate to Environment Variables**
   - In the left sidebar, click on **"App settings"**
   - Then click on **"Environment variables"** from the submenu

4. **View Environment Variables**
   - You'll see a table/list of all environment variables
   - Each variable shows:
     - **Key**: The variable name (e.g., `REACT_APP_API_URL`)
     - **Value**: The variable value (masked for security - click "Show" to reveal)
     - **Environment**: Which environment it applies to (Production, Development, etc.)

5. **View Specific Environment**
   - Use the dropdown at the top to filter by environment (Production, Development, etc.)
   - This shows only variables for that specific environment

### Method 2: Via AWS CLI

1. **Install AWS CLI** (if not already installed)
   ```bash
   # macOS
   brew install awscli
   
   # Or download from: https://aws.amazon.com/cli/
   ```

2. **Configure AWS CLI**
   ```bash
   aws configure
   ```
   - Enter your AWS Access Key ID
   - Enter your AWS Secret Access Key
   - Enter your default region (e.g., `us-east-1`)
   - Enter default output format (e.g., `json`)

3. **List Your Amplify Apps**
   ```bash
   aws amplify list-apps
   ```
   - Note your app ID from the output

4. **Get Environment Variables**
   ```bash
   # Replace APP_ID with your actual app ID
   aws amplify get-app --app-id YOUR_APP_ID
   ```

5. **Get Environment Variables for a Branch**
   ```bash
   # Replace APP_ID and BRANCH_NAME with your values
   aws amplify get-branch \
     --app-id YOUR_APP_ID \
     --branch-name main
   ```

### Method 3: Check in Build Logs

1. **Go to Your App in Amplify Console**
2. **Click on "Deployments" tab**
3. **Click on a recent deployment**
4. **Click on "View logs"**
5. **Look for environment variable references in the build logs**
   - Note: Values are usually masked for security

### Method 4: Check in Application Code (Runtime)

If you want to verify what environment variables are actually available at runtime:

1. **Add a temporary debug endpoint** (for backend):
   ```javascript
   // In your backend code
   app.get('/api/debug/env', (req, res) => {
     res.json({
       NODE_ENV: process.env.NODE_ENV,
       FRONTEND_URL: process.env.FRONTEND_URL,
       // Add other variables you want to check (be careful with secrets!)
     });
   });
   ```

2. **Check in browser console** (for frontend):
   ```javascript
   // In browser console on your deployed site
   console.log('API URL:', process.env.REACT_APP_API_URL);
   // Note: Only variables starting with REACT_APP_ are available in browser
   ```

## Important Notes

### Security
- **Never expose sensitive values** (passwords, API keys, secrets) in logs or client-side code
- AWS Amplify masks sensitive values in the console
- Use AWS Secrets Manager for highly sensitive data

### Environment Variable Naming
- **Frontend (React)**: Must start with `REACT_APP_` to be accessible in the browser
  - Example: `REACT_APP_API_URL`
- **Backend (Node.js)**: Can be any name
  - Example: `FRONTEND_URL`, `MONGODB_URI`, `JWT_SECRET`

### Common Environment Variables to Check

**Frontend:**
- `REACT_APP_API_URL` - Backend API URL
- `REACT_APP_ENVIRONMENT` - Environment name
- `NODE_ENV` - Node environment (usually set automatically)

**Backend:**
- `FRONTEND_URL` - Frontend URL for CORS
- `ALLOWED_ORIGINS` - Allowed CORS origins
- `MONGODB_URI` - MongoDB connection string
- `JWT_SECRET` - JWT signing secret
- `NODE_ENV` - Node environment
- `PORT` - Server port

## Troubleshooting

### Variables Not Showing Up
1. **Check the correct environment** (Production vs Development)
2. **Verify variable names** are correct (case-sensitive)
3. **Redeploy** after adding/changing variables
4. **Check build logs** for any errors

### Variables Not Working in Code
1. **Frontend**: Ensure variables start with `REACT_APP_`
2. **Backend**: Restart the service after adding variables
3. **Check for typos** in variable names
4. **Verify the environment** matches where variables are set

### Can't See Variable Values
- AWS Amplify masks sensitive values for security
- Click "Show" button next to the variable to reveal the value
- You need appropriate permissions to view values

## Quick Reference

**Console URL Pattern:**
```
https://console.aws.amazon.com/amplify/home?region=YOUR_REGION#/YOUR_APP_ID
```

**Direct Link to Environment Variables:**
```
https://console.aws.amazon.com/amplify/home?region=YOUR_REGION#/YOUR_APP_ID/settings/environment-variables
```

Replace:
- `YOUR_REGION` with your AWS region (e.g., `us-east-1`)
- `YOUR_APP_ID` with your Amplify app ID


# Fix: APIs Still Pointing to Localhost

## Problem
APIs are still pointing to `localhost:3002` even after deployment.

## Root Cause
The code was checking `process.env.NODE_ENV === 'production'` to determine the API URL, but `NODE_ENV` may not be reliably available in the browser at runtime.

## Solution Applied

### 1. Updated Fallback Logic
Changed from checking `NODE_ENV` to checking the actual hostname:
- If `REACT_APP_API_URL` is set → use it
- If hostname is NOT localhost → use production URL (`https://adhar-pan-kyc-1.onrender.com/api`)
- If hostname IS localhost → use localhost URL (`http://localhost:3002/api`)

### 2. Files Updated
- ✅ `frontend/src/services/api.ts` - Main API service
- ✅ `frontend/src/components/Layout/Layout.tsx` - Logo API URL
- ✅ `frontend/src/pages/AadhaarVerification/AadhaarVerification.tsx` - 3 API endpoints
- ✅ `frontend/src/pages/AadhaarVerification/AadhaarVerificationRecords.tsx` - Records API
- ✅ `amplify.yml` - Explicitly set NODE_ENV during build

## How to Fix in AWS Amplify

### Step 1: Set Environment Variable in AWS Amplify

1. Go to [AWS Amplify Console](https://console.aws.amazon.com/amplify/)
2. Select your **frontend app**
3. Click **"App settings"** → **"Environment variables"**
4. Add/Update the following variable:
   ```
   Key: REACT_APP_API_URL
   Value: https://adhar-pan-kyc-1.onrender.com/api
   Environment: Production (or All)
   ```
5. Click **"Save"**

### Step 2: Redeploy

1. Go to **"Deployments"** tab
2. Click **"Redeploy this version"** or wait for the next automatic deployment
3. Wait for deployment to complete

### Step 3: Verify

1. Open your deployed app in the browser
2. Open browser console (F12)
3. You should see:
   ```
   🔗 API Base URL: https://adhar-pan-kyc-1.onrender.com/api
   🔗 REACT_APP_API_URL: https://adhar-pan-kyc-1.onrender.com/api
   ```
4. Check Network tab to verify API calls are going to `https://adhar-pan-kyc-1.onrender.com/api`

## How It Works Now

The new logic automatically detects if you're running locally or in production:

```javascript
// If REACT_APP_API_URL is set, use it (highest priority)
if (process.env.REACT_APP_API_URL) {
  return process.env.REACT_APP_API_URL;
}

// Check if we're in production by hostname
const isProduction = window.location.hostname !== 'localhost' && 
                     window.location.hostname !== '127.0.0.1' &&
                     !window.location.hostname.startsWith('192.168.');

// Use production URL if in production, otherwise localhost
return isProduction ? 'https://adhar-pan-kyc-1.onrender.com/api' : 'http://localhost:3002/api';
```

## Testing

### Local Development
- When running `npm start` on `localhost:3000`
- API calls will go to: `http://localhost:3002/api` ✅

### Production (AWS Amplify)
- When deployed to `https://adhar-pan-kyc-1.onrender.com`
- API calls will go to: `https://adhar-pan-kyc-1.onrender.com/api` ✅
- Even if `REACT_APP_API_URL` is not set, it will use production URL based on hostname

## Troubleshooting

### Still seeing localhost?
1. **Clear browser cache** - Hard refresh (Ctrl+Shift+R or Cmd+Shift+R)
2. **Check environment variable** - Verify `REACT_APP_API_URL` is set in AWS Amplify
3. **Check build logs** - Look for any errors during build
4. **Check browser console** - Look for the API URL log message
5. **Verify deployment** - Make sure the latest code is deployed

### Environment Variable Not Working?
1. Ensure variable name is exactly: `REACT_APP_API_URL` (case-sensitive)
2. Ensure it's set for the correct environment (Production)
3. Redeploy after adding/changing the variable
4. Variables starting with `REACT_APP_` are embedded at build time

## Quick Checklist

- [ ] Set `REACT_APP_API_URL=https://adhar-pan-kyc-1.onrender.com/api` in AWS Amplify
- [ ] Redeploy the frontend app
- [ ] Clear browser cache
- [ ] Check browser console for API URL
- [ ] Verify API calls in Network tab
- [ ] Test API endpoints are working


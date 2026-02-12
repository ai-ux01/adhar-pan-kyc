# Deployment Configuration

## Current Deployment URLs

### Frontend (Vercel)
- **URL:** `https://adhar-pan-kyc.vercel.app`
- **Platform:** Vercel

### Backend (Render)
- **URL:** `https://adhar-pan-kyc-1.onrender.com`
- **Platform:** Render

## Environment Variables

### Frontend Environment Variables (Vercel)

Set these in your Vercel project settings → Environment Variables:

```bash
REACT_APP_API_URL=https://adhar-pan-kyc-1.onrender.com/api
REACT_APP_ENVIRONMENT=production
```

### Backend Environment Variables (Render)

Set these in your Render dashboard → Your Service → Environment:

#### Required Variables:
```bash
NODE_ENV=production
MONGODB_URI=your-mongodb-connection-string
JWT_SECRET=your-jwt-secret
ENCRYPTION_KEY=your-32-character-encryption-key
PORT=10000
```

#### CORS Configuration:
```bash
# Frontend URL for CORS
FRONTEND_URL=https://adhar-pan-kyc.vercel.app

# Optional: Additional allowed origins (comma-separated)
ALLOWED_ORIGINS=https://adhar-pan-kyc.vercel.app
```

**Note:** The CORS configuration automatically allows all `*.vercel.app` domains, so setting `FRONTEND_URL` is optional but recommended for explicit configuration.

## CORS Configuration

The backend CORS is configured to automatically allow:
- ✅ All `*.vercel.app` domains (via regex pattern)
- ✅ All `*.netlify.app` domains (via regex pattern)
- ✅ Any domains specified in `FRONTEND_URL` or `ALLOWED_ORIGINS`

Your frontend at `https://adhar-pan-kyc.vercel.app` will automatically be allowed to make requests to the backend.

## Testing the Connection

### Test CORS from Browser Console

Open your browser console on `https://adhar-pan-kyc.vercel.app` and run:

```javascript
fetch('https://adhar-pan-kyc-1.onrender.com/api/health', {
  method: 'GET',
  credentials: 'include'
})
.then(response => response.json())
.then(data => console.log('✅ CORS OK:', data))
.catch(error => console.error('❌ CORS Error:', error));
```

### Expected Response:
```json
{
  "status": "OK",
  "timestamp": "2025-11-04T...",
  "uptime": 123.45,
  "environment": "production"
}
```

## Troubleshooting

### CORS Errors

If you see CORS errors:

1. **Check Backend Logs on Render:**
   - Look for messages like: `CORS blocked origin: https://...`
   - This indicates an origin was blocked

2. **Verify Environment Variables:**
   - Ensure `FRONTEND_URL` is set correctly in Render
   - Ensure `REACT_APP_API_URL` is set correctly in Vercel

3. **Check Backend CORS Configuration:**
   - The regex pattern `/^https:\/\/.*\.vercel\.app$/` should match your frontend
   - Verify the backend has restarted after setting environment variables

### Connection Timeout

If requests timeout:

1. **Render Free Tier:**
   - Render free tier services spin down after 15 minutes of inactivity
   - First request may take 30-60 seconds to wake up the service
   - Consider upgrading to paid tier for always-on service

2. **Check Render Service Status:**
   - Visit Render dashboard and check if service is running
   - Check service logs for any errors

### Environment Variable Issues

If environment variables aren't working:

1. **Vercel:**
   - Environment variables must be set in Vercel dashboard
   - Redeploy after adding/changing variables
   - Variables must start with `REACT_APP_` to be available in React

2. **Render:**
   - Environment variables must be set in Render dashboard
   - Service will restart automatically after adding variables
   - Check that variables are set for the correct environment (Production)

## Quick Setup Checklist

### Frontend (Vercel)
- [ ] Set `REACT_APP_API_URL=https://adhar-pan-kyc-1.onrender.com/api`
- [ ] Redeploy frontend
- [ ] Test API connection

### Backend (Render)
- [ ] Set `FRONTEND_URL=https://adhar-pan-kyc.vercel.app`
- [ ] Set all required environment variables (MongoDB, JWT, etc.)
- [ ] Wait for service to restart
- [ ] Test health endpoint
- [ ] Test CORS from frontend

## Additional Notes

- **Backend URL:** The backend URL is already configured in the frontend code as a fallback, so it will work even if `REACT_APP_API_URL` is not set
- **CORS:** The regex pattern automatically allows your Vercel frontend, so CORS should work out of the box
- **HTTPS:** Both Vercel and Render provide HTTPS by default, which is required for secure API calls


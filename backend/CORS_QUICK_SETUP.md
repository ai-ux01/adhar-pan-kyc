# Quick CORS Setup for Production

## Current Configuration

Your frontend is deployed at: **https://adhar-pan-kyc.vercel.app**

## Automatic Configuration

The CORS configuration now **automatically allows** all `*.vercel.app` domains, so your frontend URL should work without any additional configuration!

The regex pattern `/^https:\/\/.*\.vercel\.app$/` will match:
- ✅ `https://adhar-pan-kyc.vercel.app`
- ✅ `https://adhar-pan-kyc.vercel.app/` (trailing slash handled)
- ✅ Any other `*.vercel.app` domain

## Manual Configuration (Optional)

If you want to explicitly set the `FRONTEND_URL` environment variable in your production backend deployment:

### For Vercel Backend
1. Go to your Vercel project settings
2. Navigate to "Environment Variables"
3. Add:
   ```
   FRONTEND_URL=https://adhar-pan-kyc.vercel.app
   ```
4. Redeploy your backend

### For Railway
1. Go to your Railway project
2. Navigate to "Variables" tab
3. Add:
   ```
   FRONTEND_URL=https://adhar-pan-kyc.vercel.app
   ```
4. Redeploy

### For Render
1. Go to your Render dashboard
2. Select your service
3. Go to "Environment" tab
4. Add:
   ```
   FRONTEND_URL=https://adhar-pan-kyc.vercel.app
   ```
5. Save and redeploy

### For Other Platforms
Set the environment variable:
```
FRONTEND_URL=https://adhar-pan-kyc.vercel.app
```

## Testing

After deployment, test CORS by opening your browser console on `https://adhar-pan-kyc.vercel.app` and running:

```javascript
fetch('https://your-backend-url.com/api/health', {
  method: 'GET',
  credentials: 'include'
})
.then(response => console.log('✅ CORS OK:', response))
.catch(error => console.error('❌ CORS Error:', error));
```

## Notes

- Trailing slashes are automatically handled (both `https://adhar-pan-kyc.vercel.app` and `https://adhar-pan-kyc.vercel.app/` will work)
- The regex pattern ensures all Vercel deployments are automatically allowed
- You don't need to set `FRONTEND_URL` if you're using Vercel (it's automatically matched)
- Set `FRONTEND_URL` if you want to be explicit or use it for other purposes (email links, etc.)


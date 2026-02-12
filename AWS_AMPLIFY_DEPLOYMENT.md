# AWS Amplify Deployment Guide

This guide will help you deploy the frontend React application to AWS Amplify.

## Prerequisites

1. AWS Account
2. GitHub repository connected (or GitLab/Bitbucket)
3. Backend API already deployed (currently on Render: `https://adhar-pan-kyc-1.onrender.com`)

## Step 1: Connect Repository to AWS Amplify

1. Go to [AWS Amplify Console](https://console.aws.amazon.com/amplify/)
2. Click **"New app"** → **"Host web app"**
3. Choose your Git provider (GitHub, GitLab, or Bitbucket)
4. Authorize AWS Amplify to access your repository
5. Select your repository: `adhar-pan-kyc` (or your repo name)
6. Select the branch: `main`

## Step 2: Configure Build Settings

AWS Amplify will auto-detect the `amplify.yml` file in the root directory. The configuration is already set up:

- **Base directory**: Root (automatically handles `frontend/` directory)
- **Build command**: `cd frontend && npm ci && npm run build`
- **Output directory**: `frontend/build`

### Manual Configuration (if auto-detection fails):

1. In Amplify Console, go to **App settings** → **Build settings**
2. Click **"Edit"** and use this configuration:

```yaml
version: 1
frontend:
  phases:
    preBuild:
      commands:
        - cd frontend
        - npm ci
    build:
      commands:
        - npm run build
  artifacts:
    baseDirectory: frontend/build
    files:
      - '**/*'
  cache:
    paths:
      - frontend/node_modules/**/*
      - frontend/.npm/**/*
```

## Step 3: Configure Environment Variables

In AWS Amplify Console, go to **App settings** → **Environment variables** and add:

### Required Environment Variables:

```bash
REACT_APP_API_URL=https://adhar-pan-kyc-1.onrender.com/api
REACT_APP_ENVIRONMENT=production
NODE_ENV=production
```

### Optional Environment Variables:

```bash
# If you have any other frontend-specific environment variables
REACT_APP_SOME_OTHER_VAR=value
```

**Important**: All React environment variables must start with `REACT_APP_` to be accessible in the browser.

## Step 4: Configure Custom Domain (Optional)

1. In Amplify Console, go to **App settings** → **Domain management**
2. Click **"Add domain"**
3. Enter your domain name
4. Follow the DNS configuration instructions
5. SSL certificate will be automatically provisioned by AWS

## Step 5: Configure Redirects and Rewrites

The `frontend/public/_redirects` file is already configured for React Router. AWS Amplify will automatically use this file.

If you need to add custom redirects, update `frontend/public/_redirects`:

```
# React Router - handle client-side routing
/*    /index.html   200

# API proxy (if needed)
/api/*  https://adhar-pan-kyc-1.onrender.com/api/:splat  200
```

## Step 6: Deploy

1. Click **"Save and deploy"** in Amplify Console
2. AWS Amplify will:
   - Install dependencies
   - Build the React app
   - Deploy to a CloudFront CDN
   - Provide a URL like: `https://main.xxxxx.amplifyapp.com`

## Step 7: Update Backend CORS Configuration

Make sure your backend (Render) allows requests from the Amplify domain:

1. Go to Render dashboard → Your backend service → Environment
2. Add the Amplify domain to `ALLOWED_ORIGINS`:

```bash
ALLOWED_ORIGINS=https://main.xxxxx.amplifyapp.com,https://adhar-pan-kyc.vercel.app
```

Or update `FRONTEND_URL` if you're using a custom domain:

```bash
FRONTEND_URL=https://your-custom-domain.com
```

## Step 8: Continuous Deployment

AWS Amplify automatically deploys on every push to the connected branch:

- **Main branch**: Deploys to production
- **Other branches**: Creates preview deployments

## Troubleshooting

### Build Fails

1. Check build logs in Amplify Console
2. Verify Node.js version (should be 18+)
3. Check if all dependencies are in `package.json`
4. Ensure `amplify.yml` is in the root directory

### Environment Variables Not Working

1. Ensure variables start with `REACT_APP_`
2. Redeploy after adding/changing variables
3. Check browser console for undefined variables

### API Connection Issues

1. Verify `REACT_APP_API_URL` is set correctly
2. Check backend CORS configuration
3. Test API endpoint directly: `https://adhar-pan-kyc-1.onrender.com/api/health`

### Routing Issues (404 on refresh)

1. Ensure `_redirects` file exists in `frontend/public/`
2. Verify redirect rule: `/*    /index.html   200`
3. Check Amplify Console → Rewrites and redirects

## Cost

AWS Amplify Free Tier includes:
- 1,000 build minutes/month
- 15 GB served/month
- 5 GB stored/month

For most small to medium applications, this is sufficient.

## Performance Optimization

AWS Amplify automatically:
- ✅ Serves assets via CloudFront CDN
- ✅ Enables Gzip compression
- ✅ Caches static assets
- ✅ Provides HTTPS/SSL certificates

## Monitoring

1. Go to **Monitoring** in Amplify Console
2. View:
   - Build history
   - Deployment status
   - Access logs
   - Performance metrics

## Additional Resources

- [AWS Amplify Documentation](https://docs.amplify.aws/)
- [React Deployment Guide](https://create-react-app.dev/docs/deployment/)
- [Amplify Console Guide](https://docs.aws.amazon.com/amplify/latest/userguide/welcome.html)


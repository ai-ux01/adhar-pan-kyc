# Vercel Deployment Guide

## Prerequisites

1. **Vercel Account**: Sign up at [vercel.com](https://vercel.com) if you don't have one
2. **GitHub Repository**: Ensure your code is pushed to GitHub
3. **Environment Variables**: Prepare your environment variables (see `.vercel.env.example`)

## Deployment Options

### Option 1: Deploy via Vercel Dashboard (Recommended - Easiest)

1. **Go to Vercel Dashboard**
   - Visit [vercel.com](https://vercel.com)
   - Sign in with your GitHub account

2. **Import Project**
   - Click "Add New Project"
   - Select your GitHub repository: `avisoftkyc/adhar-pan-kyc`
   - Click "Import"

3. **Configure Project Settings**
   - **Framework Preset**: Other
   - **Root Directory**: Leave as default (root)
   - **Build Command**: `cd frontend && npm install && npm run build`
   - **Output Directory**: `frontend/build`
   - **Install Command**: `npm install`

4. **Set Environment Variables**
   - Go to Project Settings → Environment Variables
   - Add the following variables (from `.vercel.env.example`):
     ```
     MONGODB_URI=your_mongodb_connection_string
     JWT_SECRET=your_jwt_secret_key
     SANDBOX_API_KEY=your_sandbox_api_key
     SANDBOX_API_SECRET=your_sandbox_api_secret
     ENCRYPTION_KEY=your_super_secret_encryption_key_32_chars_long
     REACT_APP_API_URL=/api
     ```
   - Optionally add email configuration:
     ```
     EMAIL_HOST=smtp.gmail.com
     EMAIL_PORT=587
     EMAIL_USER=your_email@gmail.com
     EMAIL_PASS=your_app_password
     ```

5. **Deploy**
   - Click "Deploy"
   - Wait for the build to complete
   - Your app will be live at `https://your-project-name.vercel.app`

### Option 2: Deploy via Vercel CLI

**First, fix npm cache permissions (if needed):**
```bash
sudo chown -R $(whoami) ~/.npm
```

**Then install Vercel CLI:**
```bash
npm install -g vercel
# OR use npx (no installation needed)
npx vercel
```

**Deploy:**
```bash
# Login to Vercel
vercel login

# Deploy (follow prompts)
vercel

# For production deployment
vercel --prod
```

**Set Environment Variables via CLI:**
```bash
vercel env add MONGODB_URI
vercel env add JWT_SECRET
vercel env add SANDBOX_API_KEY
vercel env add SANDBOX_API_SECRET
vercel env add ENCRYPTION_KEY
vercel env add REACT_APP_API_URL
```

## Important Notes

1. **MongoDB**: You'll need a MongoDB database (MongoDB Atlas recommended for cloud hosting)
2. **API Routes**: The backend API is configured to run as serverless functions in the `/api` directory
3. **Build Process**: The frontend will be built and served as static files, while API routes run as serverless functions
4. **Environment Variables**: Make sure all required environment variables are set in Vercel dashboard

## Post-Deployment

1. **Test the Deployment**
   - Visit your Vercel URL
   - Test API endpoints at `/api/*`
   - Verify frontend loads correctly

2. **Custom Domain (Optional)**
   - Go to Project Settings → Domains
   - Add your custom domain
   - Follow DNS configuration instructions

3. **Monitor Deployments**
   - Check deployment logs in Vercel dashboard
   - Monitor function logs for API routes
   - Set up error tracking if needed

## Troubleshooting

### Build Fails
- Check build logs in Vercel dashboard
- Ensure all dependencies are in `package.json`
- Verify Node.js version compatibility (requires Node 18+)

### API Routes Not Working
- Verify `api/index.js` exists and exports correctly
- Check serverless function logs
- Ensure environment variables are set

### Frontend Not Loading
- Verify build output directory is correct (`frontend/build`)
- Check that `REACT_APP_API_URL` is set to `/api`
- Review browser console for errors

## Support

For issues, check:
- Vercel Documentation: https://vercel.com/docs
- Project README.md
- GitHub Issues


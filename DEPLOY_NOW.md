# 🚀 Quick Vercel Deployment Guide

Follow these steps to deploy your app to Vercel in 5 minutes!

## Step 1: Push to GitHub (if not already done)

```bash
git add .
git commit -m "Prepare for Vercel deployment"
git push origin main
```

## Step 2: Deploy via Vercel Dashboard

### 2.1 Go to Vercel
1. Visit [https://vercel.com](https://vercel.com)
2. Sign in with your **GitHub account**
3. Click **"Add New Project"** or **"Import Project"**

### 2.2 Import Your Repository
1. Find and select: **`avisoftkyc/adhar-pan-kyc`**
2. Click **"Import"**

### 2.3 Configure Project Settings

**Framework Preset**: Select **"Other"** or **"Vite"** (doesn't matter, we have vercel.json)

**Root Directory**: Leave as **`.`** (root)

**Build and Output Settings** (these should auto-detect from vercel.json, but verify):
- **Build Command**: `cd frontend && npm install && npm run build`
- **Output Directory**: `frontend/build`
- **Install Command**: `npm install`

**Node.js Version**: Select **18.x** or **20.x**

### 2.4 Add Environment Variables

Click **"Environment Variables"** and add these one by one:

#### Required Variables:

1. **MONGODB_URI**
   ```
   mongodb+srv://Ashul:Anshul%40123%23@cluster0.idbaui6.mongodb.net/pan_kyc_db?retryWrites=true&w=majority
   ```
   - Environments: ✅ Production, ✅ Preview, ✅ Development

2. **JWT_SECRET**
   ```
   your_super_secret_jwt_key_change-this-in-production
   ```
   - ⚠️ **Change this to a strong random string in production!**
   - Environments: ✅ Production, ✅ Preview, ✅ Development

3. **SANDBOX_API_KEY**
   ```
   key_live_6edea225e1354559b2422d3921c795cf
   ```
   - Environments: ✅ Production, ✅ Preview, ✅ Development

4. **SANDBOX_API_SECRET**
   ```
   secret_live_03078556231c41879cd6ab46e1d6a07f
   ```
   - Environments: ✅ Production, ✅ Preview, ✅ Development

5. **ENCRYPTION_KEY**
   ```
   your_super_secret_encryption_key_32_chars_long
   ```
   - ⚠️ **Must be exactly 32 characters!**
   - Environments: ✅ Production, ✅ Preview, ✅ Development

6. **REACT_APP_API_URL**
   ```
   /api
   ```
   - Environments: ✅ Production, ✅ Preview, ✅ Development

#### Optional Variables:

7. **USE_MOCK_MODE**
   ```
   false
   ```
   - Set to `false` for production
   - Environments: ✅ Production, ✅ Preview, ✅ Development

8. **SMTP_HOST** (if using email)
   ```
   smtp.gmail.com
   ```

9. **SMTP_PORT** (if using email)
   ```
   587
   ```

10. **SMTP_USER** (if using email)
    ```
    your-email@gmail.com
    ```

11. **SMTP_PASS** (if using email)
    ```
    your-app-password
    ```

### 2.5 Deploy!

1. Click **"Deploy"** button
2. Wait 2-5 minutes for the build to complete
3. 🎉 Your app will be live at `https://your-project-name.vercel.app`

## Step 3: Verify Deployment

### 3.1 Check Frontend
- Visit your Vercel URL
- The React app should load

### 3.2 Check API
- Visit `https://your-project-name.vercel.app/api/health`
- Should return a health check response

### 3.3 Test Authentication
- Try logging in
- Check browser console for any errors

## Step 4: Configure MongoDB Atlas (Important!)

Your MongoDB needs to allow connections from Vercel:

1. Go to [MongoDB Atlas](https://cloud.mongodb.com)
2. Navigate to **Network Access**
3. Click **"Add IP Address"**
4. Click **"Allow Access from Anywhere"** (for testing)
   - Or add specific Vercel IP ranges for production
5. Click **"Confirm"**

## Troubleshooting

### Build Fails
- Check build logs in Vercel dashboard
- Ensure Node.js version is 18+ in package.json
- Verify all dependencies are listed in package.json

### API Routes Return 500
- Check Function logs in Vercel dashboard
- Verify environment variables are set correctly
- Check MongoDB connection string

### Frontend Can't Connect to API
- Verify `REACT_APP_API_URL=/api` is set
- Check browser console for CORS errors
- Verify API routes are working at `/api/health`

### MongoDB Connection Fails
- Verify MongoDB Atlas allows connections from anywhere (0.0.0.0/0)
- Check connection string is correct
- Verify database user has proper permissions

## Next Steps

1. ✅ Set up custom domain (optional)
2. ✅ Configure production JWT_SECRET (change from default)
3. ✅ Set up monitoring and error tracking
4. ✅ Configure production MongoDB with restricted IP access
5. ✅ Set up CI/CD for automatic deployments

## Need Help?

- Check `VERCEL_DEPLOYMENT.md` for detailed guide
- Check `VERCEL_ENV_VARIABLES.md` for environment variable details
- Vercel Docs: https://vercel.com/docs

---

**Ready to deploy?** Go to [vercel.com](https://vercel.com) and follow Step 2! 🚀


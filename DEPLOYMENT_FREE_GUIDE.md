# 🚀 Free Deployment Guide for KYC Aadhaar App

## 📋 Prerequisites
- GitHub account
- MongoDB Atlas account (free tier)
- Vercel account (free) - **Recommended for Full-Stack**
- Render account (free tier) - Alternative
- Railway account (free tier) - Alternative

## 🎯 Deployment Strategy

### Option 1: Full-Stack on Vercel (Recommended)
- **Frontend**: Vercel (Free)
- **Backend**: Vercel Serverless Functions (Free)
- **Database**: MongoDB Atlas (Free tier)

### Option 2: Separate Services
- **Frontend**: Vercel (Free)
- **Backend**: Render (Free tier)
- **Database**: MongoDB Atlas (Free tier)

---

## 🚀 Full-Stack Deployment on Vercel (Recommended)

### Step 1: Prepare Your Repository
Your repository is already configured with:
- `vercel.json` - Main Vercel configuration
- `api/index.js` - API entry point
- `frontend/vercel.json` - Frontend build config
- `backend/api/vercel.json` - Backend API config

### Step 2: Deploy to Vercel
1. Go to [vercel.com](https://vercel.com)
2. Sign up with GitHub
3. Click "New Project"
4. Import your repository: `ashulk311-ux/adhar-pan-kyc`
5. Vercel will auto-detect the configuration

### Step 3: Set Environment Variables
In Vercel dashboard, go to Settings → Environment Variables and add:

```
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret_key
SANDBOX_API_KEY=your_sandbox_api_key
SANDBOX_API_SECRET=your_sandbox_api_secret
ENCRYPTION_KEY=your_super_secret_encryption_key_32_chars_long
REACT_APP_API_URL=/api
```

### Step 4: Deploy
1. Click "Deploy"
2. Wait for build to complete
3. Your app will be available at: `https://your-app.vercel.app`

### Step 5: Test Your Deployment
- Frontend: `https://your-app.vercel.app`
- API Health: `https://your-app.vercel.app/api/health`
- API Docs: `https://your-app.vercel.app/api`


---

## 🖥️ Frontend Deployment (Vercel) - Alternative

### Step 1: Prepare Frontend
```bash
cd frontend
npm run build
```

### Step 2: Deploy to Vercel
1. Go to [vercel.com](https://vercel.com)
2. Sign up with GitHub
3. Click "New Project"
4. Import your GitHub repository
5. Configure:
   - **Framework Preset**: Create React App
   - **Root Directory**: `frontend`
   - **Build Command**: `npm run build`
   - **Output Directory**: `build`
   - **Install Command**: `npm install`

### Step 3: Environment Variables
Add in Vercel dashboard:
```
REACT_APP_API_URL=https://your-backend-url.railway.app/api
```

### Step 4: Deploy
Click "Deploy" and get your frontend URL!

---

## ⚙️ Backend Deployment (Render) - **Recommended**

### Step 1: Prepare Backend
Your backend is already configured with `render.yaml` and `backend/render.json`.

### Step 2: Deploy to Render
1. Go to [render.com](https://render.com)
2. Sign up with GitHub
3. Click "New +" → "Web Service"
4. Connect your GitHub repository
5. Configure the service:
   - **Name**: `kyc-aadhaar-backend`
   - **Root Directory**: `backend`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Plan**: Free

### Step 3: Set Environment Variables
In Render dashboard, go to Environment tab and add:
```
NODE_ENV=production
PORT=3002
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
SANDBOX_API_KEY=your_sandbox_api_key
SANDBOX_API_SECRET=your_sandbox_api_secret
ENCRYPTION_KEY=your_super_secret_encryption_key_32_chars_long
```

### Step 4: Deploy
Click "Create Web Service" and wait for deployment.

---

## ⚙️ Backend Deployment (Railway) - Alternative

### Step 1: Prepare Backend
Ensure your `backend/package.json` has:
```json
{
  "scripts": {
    "start": "node src/server.js"
  }
}
```

### Step 2: Deploy to Railway
1. Go to [railway.app](https://railway.app)
2. Sign up with GitHub
3. Click "New Project"
4. Select "Deploy from GitHub repo"
5. Choose your repository
6. **If Railway doesn't auto-detect Node.js:**
   - Go to Settings → Deploy
   - Set **Root Directory**: `backend`
   - Set **Build Command**: `npm install`
   - Set **Start Command**: `npm start`

### Step 3: Environment Variables
Add in Railway dashboard:
```
NODE_ENV=production
PORT=3002
MONGODB_URI=your_mongodb_atlas_connection_string
JWT_SECRET=your_jwt_secret_key
JWT_EXPIRE=30d
SANDBOX_API_KEY=your_sandbox_api_key
SANDBOX_API_SECRET=your_sandbox_api_secret
```

### Step 4: Deploy
Railway will automatically deploy and give you a URL!

---

## 🗄️ Database Setup (MongoDB Atlas)

### Step 1: Create Cluster
1. Go to [mongodb.com/atlas](https://mongodb.com/atlas)
2. Create free account
3. Create free cluster (M0 Sandbox)
4. Choose region closest to your users

### Step 2: Configure Access
1. Create database user
2. Whitelist IP addresses (0.0.0.0/0 for Railway)
3. Get connection string

### Step 3: Connect
Use the connection string in your Railway environment variables.

---

## 🔗 Connect Frontend to Backend

### Update Frontend Environment
In Vercel dashboard, update:
```
REACT_APP_API_URL=https://your-railway-backend-url.railway.app/api
```

---

## 🎉 Final Steps

1. **Test your deployment**:
   - Frontend: `https://your-app.vercel.app`
   - Backend: `https://your-backend.railway.app/health`

2. **Update CORS settings** in backend if needed

3. **Test the full flow**:
   - User registration
   - Aadhaar verification
   - Records viewing

---

## 💰 Cost Breakdown

- **Frontend (Vercel)**: FREE
- **Backend (Railway)**: FREE (with $5 monthly credit)
- **Database (MongoDB Atlas)**: FREE (512MB)
- **Total Monthly Cost**: $0

---

## 🚨 Important Notes

1. **Railway Free Tier**: 
   - $5 credit monthly
   - Usually enough for small apps
   - Apps sleep after inactivity

2. **MongoDB Atlas Free Tier**:
   - 512MB storage
   - Shared clusters
   - Perfect for development/small production

3. **Vercel Free Tier**:
   - Unlimited personal projects
   - 100GB bandwidth
   - Perfect for React apps

---

## 🔧 Troubleshooting

### Common Issues:
1. **CORS errors**: Update CORS settings in backend
2. **Environment variables**: Double-check all variables are set
3. **Build failures**: Check build logs in deployment platform
4. **Database connection**: Verify MongoDB Atlas connection string
5. **Railway auto-detection fails**: 
   **Option A: Manual Configuration**
   - Set Root Directory to `backend`
   - Set Build Command to `npm install`
   - Set Start Command to `npm start`

   **Option B: Use Configuration Files (Recommended)**
   - Keep root directory as default
   - Railway will use `railway.json` and `nixpacks.toml` automatically
   - If still failing, try `Procfile` approach
6. **Railway deployment fails**:
   - Check if `package.json` exists in backend folder
   - Verify Node.js version compatibility
   - Check Railway logs for specific errors

### Support:
- Vercel: [vercel.com/docs](https://vercel.com/docs)
- Railway: [docs.railway.app](https://docs.railway.app)
- MongoDB Atlas: [docs.atlas.mongodb.com](https://docs.atlas.mongodb.com)

---

## 🎯 Success Checklist

- [ ] Frontend deployed on Vercel
- [ ] Backend deployed on Railway
- [ ] Database connected to MongoDB Atlas
- [ ] Environment variables configured
- [ ] CORS settings updated
- [ ] Full app functionality tested
- [ ] Custom domain configured (optional)

**Congratulations! Your KYC Aadhaar app is now live for FREE! 🎉**

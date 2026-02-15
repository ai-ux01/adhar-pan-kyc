# AWS Amplify Quick Start

## Quick Deployment Steps

### 1. Connect Repository
- Go to [AWS Amplify Console](https://console.aws.amazon.com/amplify/)
- Click **"New app"** → **"Host web app"**
- Connect your GitHub/GitLab/Bitbucket repository
- Select branch: `main`

### 2. Build Settings (Auto-detected)
The `amplify.yml` file is already configured. Amplify will auto-detect it.

### 3. Environment Variables
Add these in **App settings** → **Environment variables**:

```
REACT_APP_API_URL=https://adhar-pan-kyc.onrender.com/api
REACT_APP_ENVIRONMENT=production
NODE_ENV=production
```

### 4. Deploy
Click **"Save and deploy"** - that's it! 🚀

### 5. Update Backend CORS
Add your Amplify URL to Render backend environment variables:

```bash
ALLOWED_ORIGINS=https://main.xxxxx.amplifyapp.com,https://adhar-pan-kyc.vercel.app
```

<<<<<<< HEAD
#### Option B: Deploy Backend to AWS Amplify - Full Integration
Use AWS Lambda + API Gateway for backend:

1. **Setup Backend** (one-time):
```bash
# Run setup script
./setup-amplify-backend.sh

# Or manually:
amplify init
amplify add api  # Select REST API
amplify add function  # Select expressBackend
amplify push
```

2. **Environment Variables** in Amplify Console:
```
REACT_APP_API_URL=https://xxxxx.execute-api.us-east-1.amazonaws.com/dev/api
REACT_APP_ENVIRONMENT=production
NODE_ENV=production
```

#### Option C: Separate Amplify Apps (Recommended for Production) ⭐
Deploy backend and frontend as separate Amplify projects:

1. **Deploy Backend** (Lambda + API Gateway):
```bash
./deploy-backend-amplify.sh
# Or see: SEPARATE_AMPLIFY_DEPLOYMENT.md
```

2. **Deploy Frontend** (separate Amplify app):
- Create new Amplify app in Console
- Set `REACT_APP_API_URL` to backend API Gateway URL
- Deploy

📚 **See `SEPARATE_AMPLIFY_DEPLOYMENT.md` for detailed separate deployment guide**

### 4. Deploy
Click **"Save and deploy"** - that's it! 🚀

=======
>>>>>>> a5158efe72013492ec663382d99f1de4545fdc5a
## Your App Will Be Available At:
- Default: `https://main.xxxxx.amplifyapp.com`
- Custom domain: Configure in **Domain management**

## Need Help?
<<<<<<< HEAD
- Frontend deployment: See `AWS_AMPLIFY_DEPLOYMENT.md`
- Backend integration: See `AMPLIFY_BACKEND_SETUP.md`
- Separate deployment: See `SEPARATE_AMPLIFY_DEPLOYMENT.md`
=======
See `AWS_AMPLIFY_DEPLOYMENT.md` for detailed instructions.
>>>>>>> a5158efe72013492ec663382d99f1de4545fdc5a


# AWS Amplify Integration - Quick Reference

## ✅ Backend Integration Status

The AWS Amplify backend integration has been **configured and is ready to deploy**.

## 🚀 Quick Start

### Option 1: Use Existing Backend (Recommended for Quick Setup)

If your backend is already working on Render/Vercel:

1. **Deploy Frontend to Amplify:**
   - Connect repository in AWS Amplify Console
   - Set environment variable: `REACT_APP_API_URL=https://your-backend-url.com/api`
   - Deploy

2. **Update Backend CORS:**
   - Add Amplify domain to `ALLOWED_ORIGINS` on your backend

✅ **Done!** No backend changes needed.

### Option 2: Deploy Backend to AWS Amplify

For full AWS integration:

1. **Install Amplify CLI:**
   ```bash
   npm install -g @aws-amplify/cli
   ```

2. **Run Setup Script:**
   ```bash
   ./setup-amplify-backend.sh
   ```

3. **Initialize Amplify:**
   ```bash
   amplify init
   ```

4. **Add API Gateway:**
   ```bash
   amplify add api
   # Select: REST
   # Resource name: backendapi
   # Path: /api
   # Lambda function: Use existing 'expressBackend'
   ```

5. **Configure Environment Variables:**
   ```bash
   amplify update function
   # Select: expressBackend
   # Add: MONGODB_URI, JWT_SECRET, etc.
   ```

6. **Deploy:**
   ```bash
   amplify push
   ```

7. **Update Frontend:**
   - Set `REACT_APP_API_URL` in Amplify Console to API Gateway URL

## 📁 What Was Added

- ✅ Amplify backend configuration files
- ✅ Lambda function wrapper for Express backend
- ✅ API Gateway configuration
- ✅ Setup scripts and documentation
- ✅ Updated build configuration

## 📚 Documentation

- **Quick Start**: `AMPLIFY_QUICK_START.md`
- **Backend Setup**: `AMPLIFY_BACKEND_SETUP.md`
- **Integration Summary**: `AMPLIFY_BACKEND_INTEGRATION_SUMMARY.md`
- **Full Deployment Guide**: `AWS_AMPLIFY_DEPLOYMENT.md`

## 🔧 Configuration Files

All Amplify backend configuration is in:
```
amplify/
├── backend/
│   ├── api/backendapi/          # API Gateway
│   ├── function/expressBackend/  # Lambda function
│   ├── storage/kycdata/          # DynamoDB (optional)
│   └── auth/kycapp/              # Cognito (optional)
```

## ⚠️ Important Notes

1. **Backend Deployment**: Lambda functions are deployed using `amplify push`, NOT during frontend build
2. **Environment Variables**: Must be set in Lambda function configuration
3. **Database**: Can keep MongoDB Atlas or migrate to DynamoDB
4. **Authentication**: Can keep JWT or migrate to Cognito

## 🆘 Need Help?

See the detailed guides:
- `AMPLIFY_BACKEND_SETUP.md` - Step-by-step backend setup
- `AMPLIFY_QUICK_START.md` - Quick deployment guide


# Vercel Environment Variables Checklist

Use this checklist when setting up environment variables in Vercel Dashboard.

## Required Environment Variables

Copy these to your Vercel project settings (Settings → Environment Variables):

### Database Configuration
```
MONGODB_URI=mongodb+srv://Ashul:Anshul%40123%23@cluster0.idbaui6.mongodb.net/pan_kyc_db?retryWrites=true&w=majority
```
**Note**: Make sure your MongoDB Atlas allows connections from Vercel IPs (0.0.0.0/0 for testing, or specific Vercel IPs for production)

### Authentication
```
JWT_SECRET=your_super_secret_jwt_key_change-this-in-production
```
**Important**: Change this to a strong, random secret in production!

### Sandbox API Credentials
```
SANDBOX_API_KEY=key_live_6edea225e1354559b2422d3921c795cf
SANDBOX_API_SECRET=secret_live_03078556231c41879cd6ab46e1d6a07f
```

### Encryption
```
ENCRYPTION_KEY=your_super_secret_encryption_key_32_chars_long
```
**Important**: Must be exactly 32 characters long. Generate a secure random key for production.

### Frontend Configuration
```
REACT_APP_API_URL=/api
```
This tells the frontend to use relative API paths (works with Vercel routing)

### Optional: Email Configuration
```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
```

### Optional: Development Settings
```
USE_MOCK_MODE=true
```
Set to `false` in production to use real API calls

## How to Add in Vercel Dashboard

1. Go to your project on [vercel.com](https://vercel.com)
2. Click on **Settings** → **Environment Variables**
3. For each variable:
   - Click **Add New**
   - Enter the **Key** (e.g., `MONGODB_URI`)
   - Enter the **Value** (e.g., your MongoDB connection string)
   - Select environments: **Production**, **Preview**, and **Development**
   - Click **Save**
4. After adding all variables, **redeploy** your project for changes to take effect

## Security Notes

⚠️ **IMPORTANT**: 
- Never commit `.env` files to Git
- Use strong, unique secrets for production
- Rotate API keys regularly
- Restrict MongoDB access to specific IPs in production
- Use Vercel's environment variable encryption (automatic)

## Quick Copy-Paste (for Vercel Dashboard)

When adding variables, you can copy-paste these keys:

```
MONGODB_URI
JWT_SECRET
SANDBOX_API_KEY
SANDBOX_API_SECRET
ENCRYPTION_KEY
REACT_APP_API_URL
USE_MOCK_MODE
SMTP_HOST
SMTP_PORT
SMTP_USER
SMTP_PASS
```


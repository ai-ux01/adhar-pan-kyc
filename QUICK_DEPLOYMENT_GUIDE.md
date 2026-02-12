# 🚀 Quick Deployment Guide for www.ass.com/pankyc

## 🎯 **Your Deployment Path**
- **Frontend**: `https://www.ass.com/pankyc/`
- **Backend API**: `https://www.ass.com/pankyc/api/`

## ⚡ **Quick Deployment Steps**

### **Step 1: Prepare Your Application**
```bash
# Run the shared hosting deployment script
./deploy-shared-hosting.sh
```

This will create a `shared-hosting-deploy/pankyc/` folder ready for upload.

### **Step 2: Upload to Your Hosting**

#### **Option A: Using cPanel File Manager**
1. Login to your hosting control panel (cPanel)
2. Open **File Manager**
3. Navigate to `public_html`
4. Upload the entire `pankyc` folder from `shared-hosting-deploy/`
5. Extract if it's a zip file

#### **Option B: Using FTP**
1. Use FileZilla or similar FTP client
2. Connect to your hosting
3. Navigate to `/public_html/`
4. Upload `shared-hosting-deploy/pankyc/` contents to `/public_html/pankyc/`

### **Step 3: Configure Environment Variables**

Edit `/public_html/pankyc/api/.env` with your values:

```env
# Server Configuration
PORT=3000
NODE_ENV=production

# Database (Choose one option)
# Option 1: MongoDB Atlas (Recommended - Free)
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/kyc-aadhaar-app

# Option 2: Your hosting's MongoDB
# MONGODB_URI=mongodb://localhost:27017/kyc-aadhaar-app

# Security (IMPORTANT: Use strong secrets)
JWT_SECRET=your-super-secure-jwt-secret-key-minimum-32-characters
ENCRYPTION_KEY=your-32-character-encryption-key

# Email Configuration (Optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

# External APIs
PAN_KYC_API_URL=https://your-pan-api.com
AADHAAR_PAN_API_URL=https://your-aadhaar-api.com
SANDBOX_API_KEY=your-sandbox-key
SANDBOX_API_SECRET=your-sandbox-secret

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
```

### **Step 4: Set Up Database**

#### **Option A: MongoDB Atlas (Free & Recommended)**
1. Go to [mongodb.com/atlas](https://mongodb.com/atlas)
2. Create free account
3. Create new cluster
4. Get connection string
5. Update `MONGODB_URI` in `.env` file

#### **Option B: Your Hosting's MongoDB**
1. Check if your hosting provides MongoDB
2. Get connection details from hosting control panel
3. Update `MONGODB_URI` in `.env` file

### **Step 5: Start the Application**

#### **If your hosting supports Node.js:**

**Option A: SSH Access**
```bash
# SSH into your hosting
ssh your-username@your-hosting-ip

# Navigate to your app
cd public_html/pankyc/api

# Install dependencies
npm install

# Start the application
npm start
```

**Option B: cPanel Node.js Selector**
1. Go to cPanel → **Node.js Selector**
2. Click **Create Application**
3. Set **Node.js version**: 18.x
4. Set **Application root**: `public_html/pankyc/api`
5. Set **Application URL**: `pankyc`
6. Set **Application startup file**: `shared-hosting-server.js`
7. Click **Create**
8. Click **Start App**

### **Step 6: Test Your Deployment**

```bash
# Test frontend
curl https://www.ass.com/pankyc/

# Test API health
curl https://www.ass.com/pankyc/api/health

# Test in browser
# Visit: https://www.ass.com/pankyc/
```

## 🔧 **Troubleshooting**

### **Common Issues:**

1. **Application not starting**
   - Check Node.js version (needs 16+)
   - Verify all files uploaded correctly
   - Check `.env` file configuration

2. **API not responding**
   - Ensure Node.js application is running
   - Check if port 3000 is accessible
   - Verify API routes in browser

3. **Database connection failed**
   - Check MongoDB connection string
   - Verify database credentials
   - Ensure database service is running

4. **Frontend not loading**
   - Check if all files uploaded to correct directory
   - Verify `.htaccess` file is present
   - Check browser console for errors

### **Check Logs:**
```bash
# Application logs
tail -f public_html/pankyc/api/logs/combined.log

# Error logs
tail -f public_html/pankyc/api/logs/error.log
```

## 📋 **Final Checklist**

- [ ] All files uploaded to `/public_html/pankyc/`
- [ ] Environment variables configured in `.env`
- [ ] Database connection working
- [ ] Node.js application started
- [ ] Frontend accessible at `https://www.ass.com/pankyc/`
- [ ] API responding at `https://www.ass.com/pankyc/api/health`
- [ ] SSL certificate working (if applicable)

## 🎉 **Success!**

Your KYC Aadhaar App is now live at:
- **Frontend**: https://www.ass.com/pankyc/
- **API**: https://www.ass.com/pankyc/api/

## 🆘 **Need Help?**

1. **Check the detailed guide**: `SHARED_HOSTING_DEPLOYMENT.md`
2. **Review deployment instructions**: `shared-hosting-deploy/DEPLOYMENT_INSTRUCTIONS.txt`
3. **Check application logs** for specific errors
4. **Verify file permissions** (644 for files, 755 for directories)
5. **Test individual components** (database, API, frontend)

## 💡 **Pro Tips**

1. **Use MongoDB Atlas** for reliable database hosting
2. **Set up regular backups** of your application
3. **Monitor application logs** regularly
4. **Keep dependencies updated** for security
5. **Use strong passwords** and secrets in production



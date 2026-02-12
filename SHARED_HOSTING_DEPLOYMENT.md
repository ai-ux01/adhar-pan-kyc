# 🚀 Deploying KYC Aadhaar App on Shared Hosting (Subdirectory)

## 🎯 **Deployment Structure**

Your application will be accessible at:
- **Frontend**: `https://www.ass.com/pankyc/`
- **Backend API**: `https://www.ass.com/pankyc/api/`

## 📁 **Directory Structure on Your Hosting**

```
public_html/
├── pankyc/                    # Your app directory
│   ├── index.html            # Frontend build
│   ├── static/               # Frontend assets
│   ├── api/                  # Backend API
│   │   ├── server.js         # Main server file
│   │   ├── package.json      # Backend dependencies
│   │   ├── src/              # Backend source code
│   │   └── uploads/          # File uploads
│   └── .htaccess             # Apache configuration
```

## 🛠️ **Step-by-Step Deployment**

### **Step 1: Prepare Your Application for Shared Hosting**

First, let's modify the application for shared hosting deployment:

#### **1.1 Update Frontend Configuration**

Create a new file for shared hosting build:

```bash
# In your local project
cd frontend
```

Create `frontend/public/_redirects`:
```bash
# Handle client-side routing
/*    /index.html   200
```

#### **1.2 Update Backend for Subdirectory**

We need to modify the backend to work in a subdirectory. Let me create the necessary files:

```bash
# Create shared hosting specific files
```

### **Step 2: Build for Shared Hosting**

```bash
# Build frontend with correct base path
cd frontend
npm run build

# The build will be in frontend/build/
```

### **Step 3: Prepare Backend for Shared Hosting**

Create a new server file specifically for shared hosting:

```javascript
// backend/shared-hosting-server.js
const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const connectDB = require('./src/config/database');
const logger = require('./src/utils/logger');
const errorHandler = require('./src/middleware/errorHandler');

// Import routes
const authRoutes = require('./src/routes/auth');
const userRoutes = require('./src/routes/users');
const panKycRoutes = require('./src/routes/panKyc');
const aadhaarPanRoutes = require('./src/routes/aadhaarPan');
const adminRoutes = require('./src/routes/admin');
const auditRoutes = require('./src/routes/audit');
const dashboardRoutes = require('./src/routes/dashboard');

const app = express();

// Connect to MongoDB
connectDB();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false, // Disable for shared hosting
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// CORS configuration for subdirectory
app.use(cors({
  origin: ['https://www.ass.com', 'https://ass.com'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests from this IP, please try again later.' }
});
app.use('/api/', limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Serve static files from uploads
app.use('/api/uploads', express.static(path.join(__dirname, 'uploads')));

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'production'
  });
});

// API routes with /api prefix
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/pan-kyc', panKycRoutes);
app.use('/api/aadhaar-pan', aadhaarPanRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/audit', auditRoutes);
app.use('/api/dashboard', dashboardRoutes);

// Serve frontend static files
app.use(express.static(path.join(__dirname, '../frontend/build')));

// Handle client-side routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/build/index.html'));
});

// Error handling middleware
app.use(errorHandler);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  logger.info(`Server started on port ${PORT}`);
});
```

### **Step 4: Create Package.json for Shared Hosting**

```json
{
  "name": "kyc-aadhaar-shared-hosting",
  "version": "1.0.0",
  "description": "KYC Aadhaar App for Shared Hosting",
  "main": "shared-hosting-server.js",
  "scripts": {
    "start": "node shared-hosting-server.js",
    "dev": "nodemon shared-hosting-server.js"
  },
  "dependencies": {
    "express": "^4.21.2",
    "cors": "^2.8.5",
    "helmet": "^7.0.0",
    "express-rate-limit": "^6.10.0",
    "mongoose": "^7.5.0",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "dotenv": "^16.3.1",
    "multer": "^1.4.5-lts.1",
    "winston": "^3.10.0",
    "xlsx": "^0.18.5",
    "axios": "^1.11.0",
    "crypto-js": "^4.1.1",
    "express-validator": "^7.0.1",
    "morgan": "^1.10.0",
    "nodemailer": "^6.9.4"
  }
}
```

### **Step 5: Create .htaccess for Apache**

```apache
# .htaccess file for shared hosting
RewriteEngine On

# Handle client-side routing for React
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteCond %{REQUEST_URI} !^/pankyc/api/
RewriteRule ^(.*)$ /pankyc/index.html [L]

# API routes
RewriteCond %{REQUEST_URI} ^/pankyc/api/
RewriteRule ^api/(.*)$ /pankyc/api/$1 [L]

# Security headers
<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>

# Gzip compression
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/plain
    AddOutputFilterByType DEFLATE text/html
    AddOutputFilterByType DEFLATE text/xml
    AddOutputFilterByType DEFLATE text/css
    AddOutputFilterByType DEFLATE application/xml
    AddOutputFilterByType DEFLATE application/xhtml+xml
    AddOutputFilterByType DEFLATE application/rss+xml
    AddOutputFilterByType DEFLATE application/javascript
    AddOutputFilterByType DEFLATE application/x-javascript
</IfModule>

# Cache static assets
<IfModule mod_expires.c>
    ExpiresActive on
    ExpiresByType text/css "access plus 1 year"
    ExpiresByType application/javascript "access plus 1 year"
    ExpiresByType image/png "access plus 1 year"
    ExpiresByType image/jpg "access plus 1 year"
    ExpiresByType image/jpeg "access plus 1 year"
    ExpiresByType image/gif "access plus 1 year"
    ExpiresByType image/svg+xml "access plus 1 year"
</IfModule>

# File upload limits
php_value upload_max_filesize 10M
php_value post_max_size 10M
php_value max_execution_time 300
php_value max_input_time 300
```

### **Step 6: Update Frontend API Configuration**

Update `frontend/src/services/api.ts`:

```typescript
import axios from 'axios';

// Create axios instance for shared hosting
const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || '/pankyc/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache'
  },
});

// Helper function to get token from storage
const getStoredToken = (): string | null => {
  return localStorage.getItem('token') || sessionStorage.getItem('token');
};

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = getStoredToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

export default api;
```

### **Step 7: Build and Deploy**

```bash
# 1. Build frontend
cd frontend
npm run build

# 2. Create deployment package
cd ..
mkdir shared-hosting-deploy
cp -r frontend/build shared-hosting-deploy/
cp -r backend/src shared-hosting-deploy/api/
cp -r backend/uploads shared-hosting-deploy/api/
cp backend/shared-hosting-server.js shared-hosting-deploy/api/
cp backend/package.json shared-hosting-deploy/api/
cp backend/production.env shared-hosting-deploy/api/.env
cp .htaccess shared-hosting-deploy/

# 3. Create the final structure
cd shared-hosting-deploy
mkdir -p pankyc
mv build/* pankyc/
mv api pankyc/
mv .htaccess pankyc/
```

### **Step 8: Upload to Your Hosting**

#### **Option A: Using File Manager (cPanel)**
1. Login to your hosting control panel
2. Open File Manager
3. Navigate to `public_html`
4. Create folder `pankyc`
5. Upload all files from `shared-hosting-deploy/pankyc/` to `public_html/pankyc/`

#### **Option B: Using FTP**
```bash
# Upload using FTP client like FileZilla
# Upload shared-hosting-deploy/pankyc/ contents to /public_html/pankyc/
```

#### **Option C: Using Git (if supported)**
```bash
# If your hosting supports Git
git clone your-repo
cd your-repo
# Follow the build process on the server
```

### **Step 9: Configure Environment Variables**

Create `.env` file in `/public_html/pankyc/api/`:

```env
# Server Configuration
PORT=3000
NODE_ENV=production

# MongoDB Configuration (Use your hosting's MongoDB or external service)
MONGODB_URI=mongodb://your-mongodb-connection-string

# JWT Configuration
JWT_SECRET=your-super-secure-jwt-secret-key-minimum-32-characters
JWT_EXPIRES_IN=24h

# Encryption
ENCRYPTION_KEY=your-32-character-encryption-key

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

# API Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# File Upload
MAX_FILE_SIZE=10485760
ALLOWED_FILE_TYPES=xlsx,xls

# External APIs
PAN_KYC_API_URL=https://your-pan-api.com
AADHAAR_PAN_API_URL=https://your-aadhaar-api.com
SANDBOX_API_KEY=your-sandbox-key
SANDBOX_API_SECRET=your-sandbox-secret

# Fallback API
FALLBACK_API_URL=https://your-fallback-api.com

# 2FA Configuration
TOTP_SECRET=your-totp-secret

# Logging
LOG_LEVEL=warn
LOG_FILE_PATH=./logs/app.log
```

### **Step 10: Start the Application**

#### **If your hosting supports Node.js:**
```bash
# SSH into your hosting (if available)
cd /public_html/pankyc/api
npm install
npm start
```

#### **If using cPanel Node.js Selector:**
1. Go to cPanel → Node.js Selector
2. Create new application
3. Set path to `/public_html/pankyc/api`
4. Set startup file to `shared-hosting-server.js`
5. Start the application

### **Step 11: Test Your Deployment**

```bash
# Test frontend
curl https://www.ass.com/pankyc/

# Test API
curl https://www.ass.com/pankyc/api/health

# Test in browser
# Visit: https://www.ass.com/pankyc/
```

## 🔧 **Shared Hosting Specific Configurations**

### **1. Database Options**

#### **Option A: Hosting Provider's MongoDB**
- Use your hosting provider's MongoDB service
- Get connection string from hosting control panel

#### **Option B: External MongoDB Service**
- **MongoDB Atlas** (Free tier available)
- **MLab** (Free tier available)
- **Compose** (Paid service)

#### **Option C: SQLite (Simpler)**
If MongoDB is not available, we can modify the app to use SQLite:

```bash
# Install SQLite dependencies
npm install sqlite3 sequelize
```

### **2. File Upload Handling**

```javascript
// Update multer configuration for shared hosting
const multer = require('multer');

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.join(__dirname, 'uploads'))
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname)
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  }
});
```

### **3. Process Management**

For shared hosting, you might need to use PM2 or similar:

```bash
# Install PM2
npm install -g pm2

# Start with PM2
pm2 start shared-hosting-server.js --name "pankyc-app"

# Save PM2 configuration
pm2 save
pm2 startup
```

## 🛡️ **Security Considerations for Shared Hosting**

1. **Environment Variables**: Store sensitive data in `.env` file
2. **File Permissions**: Set proper file permissions (644 for files, 755 for directories)
3. **HTTPS**: Ensure SSL certificate is installed
4. **Rate Limiting**: Implement rate limiting to prevent abuse
5. **Input Validation**: Validate all user inputs
6. **File Upload Security**: Restrict file types and sizes

## 📊 **Monitoring and Maintenance**

### **1. Log Monitoring**
```bash
# Check application logs
tail -f /public_html/pankyc/api/logs/combined.log

# Check error logs
tail -f /public_html/pankyc/api/logs/error.log
```

### **2. Performance Monitoring**
- Use your hosting provider's monitoring tools
- Monitor disk usage and bandwidth
- Check application response times

### **3. Backup Strategy**
```bash
# Create backup script
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
tar -czf backup_$DATE.tar.gz /public_html/pankyc/
```

## 🆘 **Troubleshooting**

### **Common Issues:**

1. **Application not starting**
   - Check Node.js version compatibility
   - Verify all dependencies are installed
   - Check environment variables

2. **API not responding**
   - Verify API routes are correct
   - Check CORS configuration
   - Ensure backend is running

3. **File uploads not working**
   - Check file permissions
   - Verify upload directory exists
   - Check file size limits

4. **Database connection issues**
   - Verify MongoDB connection string
   - Check database credentials
   - Ensure database service is running

## ✅ **Deployment Checklist**

- [ ] Frontend built and uploaded
- [ ] Backend configured for subdirectory
- [ ] Environment variables set
- [ ] Database connection configured
- [ ] File uploads working
- [ ] SSL certificate installed
- [ ] .htaccess configured
- [ ] Application accessible at https://www.ass.com/pankyc/
- [ ] API responding at https://www.ass.com/pankyc/api/health
- [ ] All features tested

Your KYC Aadhaar App is now deployed on shared hosting! 🎉



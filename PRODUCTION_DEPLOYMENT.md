# Production Deployment Guide

This guide provides comprehensive instructions for deploying the KYC Aadhaar App to production.

## 🚀 Quick Start

### Option 1: Docker Deployment (Recommended)

```bash
# 1. Clone the repository
git clone <your-repo-url>
cd kyc-aadhaar-app

# 2. Configure environment variables
cp backend/production.env backend/.env
# Edit backend/.env with your production values

# 3. Deploy with Docker Compose
docker-compose up -d

# 4. Check status
docker-compose ps
```

### Option 2: Manual Deployment

```bash
# 1. Run the deployment script
./deploy.sh all

# 2. Configure production environment
cd dist/backend
cp production.env .env
# Edit .env with your production values

# 3. Start with PM2
npm run pm2:start
```

## 📋 Prerequisites

- Node.js 16+ and npm 8+
- MongoDB 6.0+
- PM2 (for process management)
- Nginx (for reverse proxy)
- SSL certificates (for HTTPS)

## 🔧 Environment Configuration

### Backend Environment Variables

Create a `.env` file in the backend directory with the following variables:

```env
# Server Configuration
PORT=5000
NODE_ENV=production

# Database
MONGODB_URI=mongodb://your-production-mongodb-uri

# Security (IMPORTANT: Use strong secrets)
JWT_SECRET=your-super-secure-jwt-secret-key-minimum-32-characters
ENCRYPTION_KEY=your-32-character-encryption-key

# Email Configuration
SMTP_HOST=your-production-smtp-host
SMTP_PORT=587
SMTP_USER=your-production-email@domain.com
SMTP_PASS=your-production-app-password

# API Configuration
PAN_KYC_API_URL=https://your-production-pan-api.com
AADHAAR_PAN_API_URL=https://your-production-aadhaar-api.com
SANDBOX_API_KEY=your-production-sandbox-key
SANDBOX_API_SECRET=your-production-sandbox-secret

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
```

### Frontend Environment Variables

Create a `.env.production` file in the frontend directory:

```env
GENERATE_SOURCEMAP=false
REACT_APP_API_URL=https://your-api-domain.com/api
REACT_APP_ENVIRONMENT=production
```

## 🐳 Docker Deployment

### 1. Build and Deploy

```bash
# Build the application
docker-compose build

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f
```

### 2. Update Application

```bash
# Pull latest changes
git pull

# Rebuild and restart
docker-compose down
docker-compose build
docker-compose up -d
```

### 3. Scale Backend

```bash
# Scale backend to 3 instances
docker-compose up -d --scale backend=3
```

## 🔧 Manual Deployment

### 1. Frontend Deployment

```bash
cd frontend

# Install dependencies
npm ci --only=production

# Build for production
npm run build:prod

# Deploy to web server
# Copy build/ directory to your web server
```

### 2. Backend Deployment

```bash
cd backend

# Install dependencies
npm ci --only=production

# Start with PM2
npm run pm2:start

# Monitor
pm2 monit
```

## 🌐 Nginx Configuration

### 1. Install Nginx

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nginx

# CentOS/RHEL
sudo yum install nginx
```

### 2. Configure Nginx

Copy the provided `nginx.conf` to `/etc/nginx/nginx.conf` and update:

- Replace `your-domain.com` with your actual domain
- Update SSL certificate paths
- Configure upstream servers if needed

### 3. Enable and Start

```bash
sudo nginx -t  # Test configuration
sudo systemctl enable nginx
sudo systemctl start nginx
```

## 🔒 SSL Configuration

### 1. Using Let's Encrypt (Recommended)

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d your-domain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

### 2. Manual SSL Setup

1. Obtain SSL certificates from your provider
2. Place certificates in `/etc/nginx/ssl/`
3. Update nginx configuration with correct paths

## 📊 Monitoring and Logging

### 1. PM2 Monitoring

```bash
# View process status
pm2 status

# View logs
pm2 logs

# Monitor in real-time
pm2 monit

# Restart application
pm2 restart kyc-aadhaar-backend
```

### 2. Application Logs

```bash
# Backend logs
tail -f backend/logs/combined.log
tail -f backend/logs/error.log

# Nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log
```

### 3. Health Checks

```bash
# Application health
curl https://your-domain.com/health

# Database connectivity
curl https://your-domain.com/api/health
```

## 🔧 Performance Optimization

### 1. Database Optimization

```javascript
// MongoDB indexes (run in MongoDB shell)
db.users.createIndex({ email: 1 }, { unique: true })
db.pankycs.createIndex({ batchId: 1 })
db.aadhaarpans.createIndex({ batchId: 1 })
db.audits.createIndex({ createdAt: -1 })
```

### 2. Caching

- Enable Redis for session storage
- Configure CDN for static assets
- Use browser caching for static files

### 3. Load Balancing

```nginx
# Multiple backend instances
upstream backend {
    server backend1:5000;
    server backend2:5000;
    server backend3:5000;
}
```

## 🛡️ Security Checklist

- [ ] Use strong JWT secrets (32+ characters)
- [ ] Enable HTTPS with valid SSL certificates
- [ ] Configure proper CORS origins
- [ ] Set up rate limiting
- [ ] Enable security headers
- [ ] Use environment variables for secrets
- [ ] Regular security updates
- [ ] Database access restrictions
- [ ] File upload restrictions
- [ ] Input validation and sanitization

## 🚨 Troubleshooting

### Common Issues

1. **Application won't start**
   ```bash
   # Check logs
   pm2 logs
   docker-compose logs
   
   # Check environment variables
   cat backend/.env
   ```

2. **Database connection issues**
   ```bash
   # Test MongoDB connection
   mongo "mongodb://your-connection-string"
   
   # Check network connectivity
   telnet your-mongodb-host 27017
   ```

3. **SSL certificate issues**
   ```bash
   # Test SSL configuration
   nginx -t
   
   # Check certificate validity
   openssl x509 -in /path/to/cert.pem -text -noout
   ```

### Performance Issues

1. **High memory usage**
   ```bash
   # Monitor memory
   pm2 monit
   docker stats
   
   # Restart if needed
   pm2 restart all
   ```

2. **Slow response times**
   ```bash
   # Check database performance
   db.stats()
   
   # Monitor network
   netstat -tulpn
   ```

## 📞 Support

For deployment issues:

1. Check the logs first
2. Verify environment configuration
3. Test individual components
4. Review security settings
5. Contact system administrator

## 🔄 Updates and Maintenance

### Regular Maintenance

1. **Weekly**
   - Check application logs
   - Monitor system resources
   - Review security updates

2. **Monthly**
   - Update dependencies
   - Review and rotate secrets
   - Performance analysis

3. **Quarterly**
   - Security audit
   - Backup verification
   - Disaster recovery testing

### Update Process

```bash
# 1. Backup current deployment
cp -r dist dist-backup-$(date +%Y%m%d)

# 2. Pull latest changes
git pull origin main

# 3. Deploy updates
./deploy.sh all

# 4. Test deployment
curl https://your-domain.com/health

# 5. Rollback if needed
# Restore from backup
```



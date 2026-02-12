# 🚀 Deploying KYC Aadhaar App on BigRock

## 🎯 **BigRock Hosting Options**

BigRock offers several hosting solutions suitable for your application:

### **1. VPS Hosting (Recommended)**
- **Linux VPS**: Starting from ₹299/month
- **Specs**: 1GB RAM, 1 CPU, 20GB SSD
- **Recommended**: ₹599/month (2GB RAM, 2 CPU, 40GB SSD)
- **OS**: Ubuntu 20.04/22.04 LTS

### **2. Cloud Hosting**
- **Cloud VPS**: Starting from ₹399/month
- **Better performance** and scalability
- **Auto-scaling** capabilities

### **3. Dedicated Server**
- **For high traffic** applications
- **Starting from ₹2,999/month**

## 🛠️ **Step-by-Step BigRock Deployment**

### **Step 1: Purchase BigRock VPS**

1. **Visit BigRock**: [bigrock.in](https://bigrock.in)
2. **Choose VPS Hosting**:
   - Select **Linux VPS**
   - Choose **₹599/month plan** (2GB RAM, 2 CPU, 40GB SSD)
   - Select **Ubuntu 22.04 LTS**
   - Choose **Mumbai/Delhi** data center (for India)
3. **Complete purchase** and wait for server setup (usually 15-30 minutes)

### **Step 2: Access Your Server**

1. **Get server details** from BigRock control panel:
   - Server IP address
   - Root password
   - SSH access details

2. **Connect via SSH**:
   ```bash
   ssh root@your-server-ip
   # Enter the password provided by BigRock
   ```

### **Step 3: Server Setup**

```bash
# Update system packages
apt update && apt upgrade -y

# Install Node.js 18
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
apt-get install -y nodejs

# Verify Node.js installation
node --version  # Should show v18.x.x
npm --version   # Should show 9.x.x

# Install PM2 globally
npm install -g pm2

# Install Nginx
apt install nginx -y

# Install MongoDB
wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/6.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-6.0.list
apt-get update
apt-get install -y mongodb-org

# Start and enable MongoDB
systemctl start mongod
systemctl enable mongod

# Install Git
apt install git -y

# Install UFW firewall
apt install ufw -y
ufw allow ssh
ufw allow 80
ufw allow 443
ufw --force enable
```

### **Step 4: Deploy Your Application**

```bash
# Clone your repository
git clone https://github.com/your-username/kyc-aadhaar-app.git
cd kyc-aadhaar-app

# Make deployment script executable
chmod +x deploy.sh

# Run deployment script
./deploy.sh all

# Navigate to backend directory
cd dist/backend

# Copy and configure environment file
cp production.env .env
nano .env
```

### **Step 5: Configure Environment Variables**

Edit the `.env` file with your production values:

```env
# Server Configuration
PORT=5000
NODE_ENV=production

# MongoDB Configuration
MONGODB_URI=mongodb://localhost:27017/kyc-aadhaar-app

# JWT Configuration (IMPORTANT: Use strong secrets)
JWT_SECRET=your-super-secure-jwt-secret-key-minimum-32-characters
JWT_EXPIRES_IN=24h

# Encryption (Use strong encryption key)
ENCRYPTION_KEY=your-32-character-encryption-key

# Email Configuration (Optional)
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

### **Step 6: Start the Application**

```bash
# Start backend with PM2
npm run pm2:start

# Check PM2 status
pm2 status

# View logs
pm2 logs

# Save PM2 configuration
pm2 save
pm2 startup
```

### **Step 7: Configure Nginx**

```bash
# Copy nginx configuration
cp ../../nginx.conf /etc/nginx/nginx.conf

# Edit nginx configuration
nano /etc/nginx/nginx.conf
```

Update the nginx configuration:
- Replace `your-domain.com` with your actual domain
- Update server IP if needed

```bash
# Test nginx configuration
nginx -t

# Start and enable nginx
systemctl start nginx
systemctl enable nginx
systemctl restart nginx
```

### **Step 8: Domain Setup**

1. **Buy domain from BigRock** (if not already owned):
   - Go to BigRock domain section
   - Search for your desired domain
   - Complete purchase

2. **Configure DNS**:
   - Go to BigRock DNS management
   - Add A record: `@` → `your-server-ip`
   - Add CNAME record: `www` → `your-domain.com`

### **Step 9: SSL Certificate Setup**

```bash
# Install Certbot
apt install certbot python3-certbot-nginx -y

# Get SSL certificate
certbot --nginx -d your-domain.com -d www.your-domain.com

# Test auto-renewal
certbot renew --dry-run

# Setup auto-renewal
crontab -e
# Add this line:
# 0 12 * * * /usr/bin/certbot renew --quiet
```

### **Step 10: Test Your Deployment**

```bash
# Test backend health
curl http://localhost:5000/health

# Test frontend
curl http://localhost:80

# Test with domain
curl https://your-domain.com/health
```

## 🔧 **BigRock-Specific Optimizations**

### **1. BigRock Control Panel**
- Use BigRock's control panel for:
  - Server monitoring
  - Backup management
  - Resource usage tracking
  - Support tickets

### **2. Performance Optimization**
```bash
# Optimize MongoDB for BigRock VPS
nano /etc/mongod.conf

# Add these optimizations:
storage:
  wiredTiger:
    engineConfig:
      cacheSizeGB: 0.5  # Adjust based on your RAM

# Restart MongoDB
systemctl restart mongod
```

### **3. Backup Strategy**
```bash
# Create backup script
nano /root/backup.sh

#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
mongodump --out /root/backups/mongodb_$DATE
tar -czf /root/backups/app_$DATE.tar.gz /root/kyc-aadhaar-app

# Make executable
chmod +x /root/backup.sh

# Add to crontab (daily backup at 2 AM)
crontab -e
# Add: 0 2 * * * /root/backup.sh
```

## 📊 **Monitoring and Maintenance**

### **1. Resource Monitoring**
```bash
# Check system resources
htop
df -h
free -h

# Check application status
pm2 monit
pm2 status
```

### **2. Log Monitoring**
```bash
# Application logs
pm2 logs

# Nginx logs
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log

# System logs
journalctl -u nginx -f
journalctl -u mongod -f
```

### **3. Health Checks**
```bash
# Create health check script
nano /root/health-check.sh

#!/bin/bash
# Check if application is running
if ! curl -f http://localhost:5000/health > /dev/null 2>&1; then
    echo "Application is down, restarting..."
    pm2 restart all
fi

# Make executable
chmod +x /root/health-check.sh

# Add to crontab (check every 5 minutes)
crontab -e
# Add: */5 * * * * /root/health-check.sh
```

## 💰 **BigRock Pricing**

| Plan | RAM | CPU | Storage | Price/Month | Best For |
|------|-----|-----|---------|-------------|----------|
| VPS Basic | 1GB | 1 Core | 20GB SSD | ₹299 | Testing |
| VPS Standard | 2GB | 2 Cores | 40GB SSD | ₹599 | **Recommended** |
| VPS Premium | 4GB | 2 Cores | 80GB SSD | ₹999 | High Traffic |
| Cloud VPS | 2GB | 2 Cores | 40GB SSD | ₹399 | Better Performance |

## 🛡️ **Security Checklist for BigRock**

- [ ] Change default root password
- [ ] Setup SSH key authentication
- [ ] Configure UFW firewall
- [ ] Install SSL certificate
- [ ] Regular security updates
- [ ] Strong environment variables
- [ ] Database access restrictions
- [ ] File upload restrictions
- [ ] Rate limiting enabled
- [ ] Security headers configured

## 🆘 **BigRock Support**

### **Support Channels**
- **Phone**: 1800-200-6666 (Toll-free)
- **Email**: support@bigrock.in
- **Live Chat**: Available on BigRock website
- **Knowledge Base**: BigRock help center

### **Common Issues**
1. **Server not accessible**: Check firewall settings
2. **Domain not resolving**: Verify DNS configuration
3. **SSL not working**: Check domain DNS propagation
4. **Application not starting**: Check PM2 logs and environment variables

## 🚀 **Quick Start Commands**

```bash
# Complete setup in one go
ssh root@your-bigrock-ip
apt update && apt upgrade -y
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
apt-get install -y nodejs nginx mongodb-org git ufw
npm install -g pm2
ufw allow ssh && ufw allow 80 && ufw allow 443 && ufw --force enable
git clone https://github.com/your-username/kyc-aadhaar-app.git
cd kyc-aadhaar-app && chmod +x deploy.sh && ./deploy.sh all
cd dist/backend && cp production.env .env && nano .env
npm run pm2:start && pm2 save && pm2 startup
cp ../../nginx.conf /etc/nginx/nginx.conf && nginx -t && systemctl restart nginx
apt install certbot python3-certbot-nginx -y
certbot --nginx -d your-domain.com
```

## ✅ **Deployment Checklist**

- [ ] BigRock VPS purchased and accessible
- [ ] Server updated and secured
- [ ] Node.js, MongoDB, Nginx installed
- [ ] Application deployed and configured
- [ ] Environment variables set
- [ ] PM2 process manager running
- [ ] Nginx configured and running
- [ ] Domain DNS configured
- [ ] SSL certificate installed
- [ ] Firewall configured
- [ ] Backup strategy implemented
- [ ] Monitoring setup
- [ ] Health checks working

Your KYC Aadhaar App is now ready to run on BigRock! 🎉



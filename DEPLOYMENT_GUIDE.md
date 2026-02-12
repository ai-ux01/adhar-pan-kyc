# 🚀 KYC Aadhaar App Deployment Guide

## 🎯 **Recommended Deployment Options**

### **Option 1: DigitalOcean Droplet (Recommended for Start)**

**Why DigitalOcean?**
- ✅ Simple setup and management
- ✅ Predictable pricing ($5-20/month)
- ✅ Great documentation
- ✅ Good performance
- ✅ Easy scaling

**Steps:**

1. **Create DigitalOcean Account**
   - Go to [digitalocean.com](https://digitalocean.com)
   - Sign up and add payment method
   - Get $200 free credit for new users

2. **Create Droplet**
   ```bash
   # Choose Ubuntu 22.04 LTS
   # Size: Basic $12/month (2GB RAM, 1 CPU, 50GB SSD)
   # Add SSH key for security
   ```

3. **Server Setup**
   ```bash
   # Connect to your server
   ssh root@your-server-ip
   
   # Update system
   apt update && apt upgrade -y
   
   # Install Node.js 18
   curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
   apt-get install -y nodejs
   
   # Install PM2 globally
   npm install -g pm2
   
   # Install Nginx
   apt install nginx -y
   
   # Install MongoDB
   wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | apt-key add -
   echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/6.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-6.0.list
   apt-get update
   apt-get install -y mongodb-org
   systemctl start mongod
   systemctl enable mongod
   ```

4. **Deploy Application**
   ```bash
   # Clone your repository
   git clone https://github.com/your-username/kyc-aadhaar-app.git
   cd kyc-aadhaar-app
   
   # Run deployment script
   chmod +x deploy.sh
   ./deploy.sh all
   
   # Configure environment
   cd dist/backend
   cp production.env .env
   nano .env  # Edit with your production values
   
   # Start with PM2
   npm run pm2:start
   ```

5. **Configure Nginx**
   ```bash
   # Copy nginx configuration
   cp nginx.conf /etc/nginx/nginx.conf
   
   # Update domain name in config
   nano /etc/nginx/nginx.conf
   # Replace 'your-domain.com' with your actual domain
   
   # Test and restart nginx
   nginx -t
   systemctl restart nginx
   systemctl enable nginx
   ```

6. **Setup SSL with Let's Encrypt**
   ```bash
   # Install Certbot
   apt install certbot python3-certbot-nginx -y
   
   # Get SSL certificate
   certbot --nginx -d your-domain.com
   
   # Auto-renewal
   crontab -e
   # Add: 0 12 * * * /usr/bin/certbot renew --quiet
   ```

**Total Cost**: ~$12-20/month

---

### **Option 2: Docker Deployment (Advanced)**

**Best for**: Developers familiar with Docker

1. **Server Setup** (Same as Option 1, but install Docker)
   ```bash
   # Install Docker
   curl -fsSL https://get.docker.com -o get-docker.sh
   sh get-docker.sh
   
   # Install Docker Compose
   apt install docker-compose -y
   ```

2. **Deploy with Docker**
   ```bash
   # Clone repository
   git clone https://github.com/your-username/kyc-aadhaar-app.git
   cd kyc-aadhaar-app
   
   # Configure environment
   cp backend/production.env backend/.env
   nano backend/.env  # Edit with your values
   
   # Deploy
   docker-compose up -d
   
   # Check status
   docker-compose ps
   ```

---

### **Option 3: Vercel + Railway (Easiest)**

**Best for**: Quick deployment, minimal server management

#### **Frontend on Vercel**
1. Go to [vercel.com](https://vercel.com)
2. Connect your GitHub repository
3. Configure build settings:
   ```json
   {
     "buildCommand": "cd frontend && npm run build:prod",
     "outputDirectory": "frontend/build",
     "installCommand": "cd frontend && npm ci"
   }
   ```
4. Add environment variables:
   ```
   REACT_APP_API_URL=https://your-railway-app.railway.app/api
   ```

#### **Backend on Railway**
1. Go to [railway.app](https://railway.app)
2. Connect GitHub repository
3. Add MongoDB service
4. Configure environment variables
5. Deploy automatically

**Total Cost**: Free tier available, then ~$5-10/month

---

### **Option 4: AWS (Enterprise)**

**Best for**: High scalability, enterprise features

#### **Architecture**
- **Frontend**: AWS S3 + CloudFront
- **Backend**: AWS ECS or EC2
- **Database**: AWS DocumentDB (MongoDB compatible)
- **Load Balancer**: AWS Application Load Balancer

#### **Steps**
1. Create AWS account
2. Set up VPC and security groups
3. Deploy using AWS CLI or Console
4. Configure Route 53 for DNS
5. Set up CloudWatch for monitoring

**Total Cost**: $20-100+/month depending on usage

---

## 🌍 **Domain and DNS Setup**

### **1. Buy Domain**
- **Recommended**: Namecheap, GoDaddy, or Google Domains
- **Cost**: $10-15/year for .com domains

### **2. Configure DNS**
```bash
# A Record: your-domain.com -> your-server-ip
# CNAME: www.your-domain.com -> your-domain.com
```

### **3. Update Application**
```bash
# Update nginx.conf with your domain
# Update CORS settings in backend
# Update frontend API URL
```

---

## 🔧 **Environment Configuration**

### **Backend Environment Variables**
```env
# Server
PORT=5000
NODE_ENV=production

# Database
MONGODB_URI=mongodb://localhost:27017/kyc-aadhaar-app

# Security (IMPORTANT: Generate strong secrets)
JWT_SECRET=your-super-secure-jwt-secret-key-minimum-32-characters
ENCRYPTION_KEY=your-32-character-encryption-key

# Email (Optional)
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

### **Frontend Environment Variables**
```env
GENERATE_SOURCEMAP=false
REACT_APP_API_URL=https://your-domain.com/api
REACT_APP_ENVIRONMENT=production
```

---

## 📊 **Monitoring and Maintenance**

### **1. Health Checks**
```bash
# Application health
curl https://your-domain.com/health

# Database connectivity
curl https://your-domain.com/api/health
```

### **2. Logs Monitoring**
```bash
# Application logs
pm2 logs

# Nginx logs
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log

# System logs
journalctl -u nginx -f
```

### **3. Performance Monitoring**
```bash
# System resources
htop
df -h
free -h

# PM2 monitoring
pm2 monit
```

---

## 🛡️ **Security Checklist**

- [ ] Strong passwords and secrets
- [ ] SSL certificate installed
- [ ] Firewall configured (UFW)
- [ ] Regular security updates
- [ ] Database access restricted
- [ ] File upload restrictions
- [ ] Rate limiting enabled
- [ ] Security headers configured

---

## 💰 **Cost Comparison**

| Option | Monthly Cost | Setup Difficulty | Scalability |
|--------|-------------|------------------|-------------|
| DigitalOcean VPS | $12-20 | Easy | Good |
| Docker on VPS | $12-20 | Medium | Good |
| Vercel + Railway | $5-10 | Very Easy | Limited |
| AWS | $20-100+ | Hard | Excellent |

---

## 🚀 **Quick Start (Recommended)**

**For beginners, I recommend DigitalOcean VPS:**

1. **Sign up**: [digitalocean.com](https://digitalocean.com)
2. **Create $12/month droplet** (Ubuntu 22.04)
3. **Follow Option 1 steps** above
4. **Buy domain** and point to server
5. **Setup SSL** with Let's Encrypt

**Total setup time**: 2-3 hours
**Total monthly cost**: $12-15

---

## 🆘 **Need Help?**

1. **Check logs first**: `pm2 logs` and `nginx -t`
2. **Verify environment**: Check all .env variables
3. **Test connectivity**: `curl localhost:5000/health`
4. **Review security**: Ensure firewall and SSL are working

**Common issues:**
- Port 80/443 not accessible → Check firewall
- Database connection failed → Check MongoDB status
- SSL not working → Verify domain DNS and certbot
- App not starting → Check PM2 logs and environment variables



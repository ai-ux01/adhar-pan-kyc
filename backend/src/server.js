const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config();

const connectDB = require('./config/database');
const logger = require('./utils/logger');
const errorHandler = require('./middleware/errorHandler');
const { getAllowedOrigins, getAllowedOrigin: getCorsOrigin } = require('./utils/corsHelper');

// Import routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const panKycRoutes = require('./routes/panKyc');
const aadhaarPanRoutes = require('./routes/aadhaarPan');
const aadhaarVerificationRoutes = require('./routes/aadhaarVerification');
const adminRoutes = require('./routes/admin');
const auditRoutes = require('./routes/audit');
const dashboardRoutes = require('./routes/dashboard');
const customFieldsRoutes = require('./routes/customFields');

const app = express();
const PORT = process.env.PORT || 5000;

// Connect to MongoDB
connectDB();

// Initialize scheduler service
const schedulerService = require('./services/schedulerService');
schedulerService.initialize().catch(error => {
  logger.error('Failed to initialize scheduler service:', error);
});

// Security middleware
app.use(helmet({
  contentSecurityPolicy: process.env.NODE_ENV === 'production' ? {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:", "http://localhost:3002"],
      scriptSrc: ["'self'"],
    },
  } : false,
  crossOriginResourcePolicy: { policy: "cross-origin" },
  crossOriginEmbedderPolicy: false
}));

// CORS configuration - flexible for different deployment environments

app.use(cors({
  origin: (origin, callback) => {
    const allowedOrigins = getAllowedOrigins();
    
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) {
      return callback(null, true);
    }
    
    // Check if origin matches any allowed origin
    for (const allowedOrigin of allowedOrigins) {
      if (typeof allowedOrigin === 'string') {
        if (origin === allowedOrigin) {
          return callback(null, true);
        }
      } else if (allowedOrigin instanceof RegExp) {
        if (allowedOrigin.test(origin)) {
          return callback(null, true);
        }
      }
    }
    
    // Allow origin if in development mode (for flexibility during development)
    if (process.env.NODE_ENV !== 'production') {
      return callback(null, true);
    }
    
    // Log blocked origin for debugging
    logger.warn(`CORS blocked origin: ${origin}`);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Cache-Control', 'Pragma'],
  exposedHeaders: ['Content-Length', 'X-Requested-With'],
  optionsSuccessStatus: 200
}));

// Handle preflight requests
app.options('*', cors());

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Logging middleware
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));

// Static files
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

// Logo serving endpoint (bypasses helmet restrictions)
app.get('/api/logos/:userId', (req, res) => {
  const userId = req.params.userId;
  const logoPath = path.join(__dirname, '../uploads/logos');
  
  // Set CORS headers for image serving - use same origin logic as main CORS config
  res.set({
    'Access-Control-Allow-Origin': getCorsOrigin(req.headers.origin),
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'GET',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Cross-Origin-Resource-Policy': 'cross-origin',
    'Cross-Origin-Embedder-Policy': 'unsafe-none'
  });
  
  // Find the logo file for this user
  const fs = require('fs');
  fs.readdir(logoPath, (err, files) => {
    if (err) {
      return res.status(404).json({ error: 'Logo not found' });
    }
    
    // Find the most recent logo file for this user
    const logoFiles = files.filter(file => file.startsWith('logo-'));
    if (logoFiles.length === 0) {
      return res.status(404).json({ error: 'Logo not found' });
    }
    
    // Get the most recent logo file
    const latestLogo = logoFiles.sort().pop();
    res.sendFile(path.join(logoPath, latestLogo));
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV,
  });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/pan-kyc', panKycRoutes);
app.use('/api/aadhaar-pan', aadhaarPanRoutes);
app.use('/api/aadhaar-verification', aadhaarVerificationRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/audit', auditRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/custom-fields', customFieldsRoutes);

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Route not found',
    path: req.originalUrl,
  });
});

// Error handling middleware
app.use(errorHandler);

// Export app for Vercel
module.exports = app;

// Start server only if not in Vercel environment
if (process.env.NODE_ENV !== 'production' || !process.env.VERCEL) {
  const serverPort = process.env.PORT || PORT;
  app.listen(serverPort, '0.0.0.0', () => {
    logger.info(`Server running on port ${serverPort} in ${process.env.NODE_ENV} mode`);
    console.log(`🚀 Server running on port ${serverPort} in ${process.env.NODE_ENV} mode`);
    console.log(`📊 Health check: http://localhost:${serverPort}/health`);
    console.log(`🔗 API Base URL: http://localhost:${serverPort}/api`);
  });
}

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  schedulerService.destroy();
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  schedulerService.destroy();
  process.exit(0);
});

module.exports = app;

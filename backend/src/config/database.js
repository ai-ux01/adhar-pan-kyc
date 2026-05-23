const mongoose = require('mongoose');
const logger = require('../utils/logger');

/**
 * Catch common Atlas URI mistakes before connect (no secrets logged).
 */
function validateMongoUri(uri) {
  if (!uri || typeof uri !== 'string' || !uri.trim()) {
    return {
      ok: false,
      message:
        'MONGODB_URI is missing. In Render: Environment → add MONGODB_URI with your Atlas connection string.'
    };
  }

  const trimmed = uri.trim();
  if (!trimmed.startsWith('mongodb://') && !trimmed.startsWith('mongodb+srv://')) {
    return {
      ok: false,
      message: 'MONGODB_URI must start with mongodb:// or mongodb+srv://'
    };
  }

  // user:pass@host — more than one @ usually means @ in password was not URL-encoded
  const afterScheme = trimmed.replace(/^mongodb(\+srv)?:\/\//, '');
  const atSigns = (afterScheme.match(/@/g) || []).length;
  if (atSigns > 1) {
    return {
      ok: false,
      message:
        'MONGODB_URI looks malformed: password may contain @, #, or : without URL encoding. ' +
        'Encode @ as %40, # as %23, : as %3A. Copy a fresh string from Atlas → Connect → Drivers.'
    };
  }

  return { ok: true };
}

const connectDB = async () => {
  const uri = process.env.MONGODB_URI || 'mongodb://localhost:27017/kyc-aadhaar-app';
  const isProduction = process.env.NODE_ENV === 'production';
  const usingDefaultLocal = !process.env.MONGODB_URI;

  if (isProduction && usingDefaultLocal) {
    const msg =
      'MONGODB_URI is not set on Render. Add your MongoDB Atlas connection string under Environment variables.';
    logger.error(msg);
    console.error(`❌ ${msg}`);
    process.exit(1);
  }

  const validation = validateMongoUri(process.env.MONGODB_URI || uri);
  if (!validation.ok) {
    logger.error(validation.message);
    console.error(`❌ ${validation.message}`);
    process.exit(1);
  }

  try {
    const conn = await mongoose.connect(uri, {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });

    logger.info(`MongoDB Connected: ${conn.connection.host}`);
    console.log(`🗄️  MongoDB Connected: ${conn.connection.host}`);

    // Handle connection events
    mongoose.connection.on('error', (err) => {
      logger.error('MongoDB connection error:', err);
      console.error('❌ MongoDB connection error:', err);
    });

    mongoose.connection.on('disconnected', () => {
      logger.warn('MongoDB disconnected');
      console.log('⚠️  MongoDB disconnected');
    });

    mongoose.connection.on('reconnected', () => {
      logger.info('MongoDB reconnected');
      console.log('🔄 MongoDB reconnected');
    });

    // Graceful shutdown
    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      logger.info('MongoDB connection closed through app termination');
      process.exit(0);
    });

  } catch (error) {
    logger.error('Database connection failed:', error);
    console.error('❌ Database connection failed:', error);

    if (error.name === 'MongoServerError' && error.code === 8000) {
      console.error(
        '💡 MongoDB rejected the username/password. On Render, set MONGODB_URI to the exact string from ' +
          'Atlas → Database → Connect → Drivers. If the DB password has @ # or :, URL-encode it ' +
          '(@ → %40). Reset the DB user password in Atlas if unsure.'
      );
    }

    process.exit(1);
  }
};

module.exports = connectDB;

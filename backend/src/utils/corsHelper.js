/**
 * CORS Helper Utility
 * Provides consistent CORS origin resolution across the application
 */

/**
 * Normalize URL by removing trailing slashes for CORS comparison
 * @param {string} url - URL to normalize
 * @returns {string} Normalized URL
 */
const normalizeOrigin = (url) => {
  if (!url) return url;
  return url.replace(/\/+$/, ''); // Remove trailing slashes
};

/**
 * Get allowed origins based on environment configuration
 * @returns {Array<string|RegExp>} Array of allowed origins
 */
const getAllowedOrigins = () => {
  const origins = [];
  
  // Always add avihridsys domains (works in both dev and production)
  origins.push(
    'https://www.avihridsys.info',
    'https://avihridsys.info',
    'https://www.avihridsys.in',
    'https://avihridsys.in',
    /^https:\/\/(www\.)?avihridsys\.(in|info)$/
  );
  
  if (process.env.NODE_ENV === 'production') {
    // Add environment variable origins (comma-separated)
    if (process.env.ALLOWED_ORIGINS) {
      origins.push(...process.env.ALLOWED_ORIGINS.split(',').map(origin => normalizeOrigin(origin.trim())));
    }
    
    // Add FRONTEND_URL if specified (normalized)
    if (process.env.FRONTEND_URL) {
      origins.push(normalizeOrigin(process.env.FRONTEND_URL));
    }
    
    // Always add Vercel/Netlify/Amplify regex patterns for flexibility
    origins.push(
      /^https:\/\/.*\.vercel\.app$/,
      /^https:\/\/.*\.netlify\.app$/,
      /^https:\/\/.*\.amplifyapp\.com$/
    );
    
    // Add default Vercel URLs if no custom origins specified
    if (origins.filter(o => typeof o === 'string').length === 0) {
      origins.push(
        'https://kyc-aadhaar-app.vercel.app',
        'https://kyc-aadhaar-app-ashuls-projects-2dabf902.vercel.app',
        'https://adhar-pan-kyc.vercel.app'
      );
    }
    
    return origins;
  } else {
    // Development origins
    const devOrigins = ['http://localhost:3000', 'http://127.0.0.1:3000'];
    
    // Add custom dev origins if specified
    if (process.env.DEV_ALLOWED_ORIGINS) {
      devOrigins.push(...process.env.DEV_ALLOWED_ORIGINS.split(',').map(origin => normalizeOrigin(origin.trim())));
    }
    
    // Merge with avihridsys domains
    return [...origins, ...devOrigins];
  }
};

/**
 * Get the allowed origin for a specific request
 * @param {string} requestOrigin - The origin from the request headers
 * @returns {string} The allowed origin for the response header
 */
const getAllowedOrigin = (requestOrigin) => {
  if (!requestOrigin) {
    const frontendUrl = process.env.FRONTEND_URL;
    return normalizeOrigin(frontendUrl) || (process.env.NODE_ENV === 'production' ? '*' : 'http://localhost:3000');
  }
  
  // Normalize the request origin for comparison
  const normalizedRequestOrigin = normalizeOrigin(requestOrigin);
  const allowedOrigins = getAllowedOrigins();
  
  // Check if origin matches any allowed origin
  for (const allowedOrigin of allowedOrigins) {
    if (typeof allowedOrigin === 'string') {
      const normalizedAllowedOrigin = normalizeOrigin(allowedOrigin);
      if (normalizedRequestOrigin === normalizedAllowedOrigin) {
        return requestOrigin; // Return original requestOrigin (with or without trailing slash)
      }
    } else if (allowedOrigin instanceof RegExp) {
      if (allowedOrigin.test(normalizedRequestOrigin)) {
        return requestOrigin; // Return original requestOrigin
      }
    }
  }
  
  // In development, allow any origin for flexibility
  if (process.env.NODE_ENV !== 'production') {
    return requestOrigin;
  }
  
  // Fallback for production
  const frontendUrl = process.env.FRONTEND_URL;
  return normalizeOrigin(frontendUrl) || '*';
};

/**
 * Get the frontend URL for QR codes and redirects
 * Priority: FRONTEND_URL env var > Production URL (always production, no localhost)
 * @returns {string} Frontend URL
 */
const getFrontendUrl = () => {
  const logger = require('./logger');
  
  // First priority: FRONTEND_URL environment variable
  if (process.env.FRONTEND_URL) {
    const url = normalizeOrigin(process.env.FRONTEND_URL);
    // CRITICAL: Never allow localhost in production
    if (url && url.includes('localhost')) {
      logger.warn(`QR Code: FRONTEND_URL contains localhost (${url}), overriding to production URL`);
      const productionUrl = 'https://www.avihridsys.in';
      logger.info(`QR Code: Using production URL (override): ${productionUrl}`);
      return productionUrl;
    }
    logger.info(`QR Code: Using FRONTEND_URL from env: ${url}`);
    return url;
  }
  
  // Always use production URL - never localhost
  // This ensures QR codes always work in production, even if env vars aren't set
  const url = 'https://www.avihridsys.in';
  logger.info(`QR Code: Using production URL (default): ${url}`);
  logger.info(`QR Code: NODE_ENV=${process.env.NODE_ENV}, PORT=${process.env.PORT}, FRONTEND_URL=${process.env.FRONTEND_URL || 'not set'}`);
  
  // Final safety check - never return localhost
  if (url && url.includes('localhost')) {
    logger.error(`QR Code: CRITICAL - Production URL contains localhost! This should never happen.`);
    return 'https://www.avihridsys.in';
  }
  
  return url;
};

module.exports = {
  getAllowedOrigins,
  getAllowedOrigin,
  normalizeOrigin,
  getFrontendUrl
};


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
  if (process.env.NODE_ENV === 'production') {
    const origins = [];
    
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
    
    return devOrigins;
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

module.exports = {
  getAllowedOrigins,
  getAllowedOrigin,
  normalizeOrigin
};


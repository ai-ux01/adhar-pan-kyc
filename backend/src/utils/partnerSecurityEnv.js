const logger = require('./logger');

/**
 * Fail fast in production when partner security env is misconfigured.
 */
function validatePartnerSecurityEnv() {
  if (process.env.NODE_ENV !== 'production') {
    return;
  }

  const errors = [];

  if (!process.env.ENCRYPTION_KEY || String(process.env.ENCRYPTION_KEY).length < 16) {
    errors.push('ENCRYPTION_KEY must be set (min 16 characters) in production');
  }

  const pepper = process.env.PARTNER_AADHAAR_HASH_PEPPER || process.env.ENCRYPTION_KEY;
  if (!pepper || pepper === 'change-this-to-a-long-random-string') {
    errors.push('PARTNER_AADHAAR_HASH_PEPPER must be set to a strong unique value in production');
  }

  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.includes('change-this')) {
    errors.push('JWT_SECRET must be set to a strong value in production');
  }

  if (errors.length > 0) {
    errors.forEach((message) => logger.error(`Security config: ${message}`));
    process.exit(1);
  }
}

module.exports = { validatePartnerSecurityEnv };

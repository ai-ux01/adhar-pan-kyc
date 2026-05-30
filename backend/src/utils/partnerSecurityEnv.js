const logger = require('./logger');

const WEAK_JWT_SECRETS = new Set([
  'your-super-secret-jwt-key-change-this-in-production',
  'your_super_secret_jwt_key_change-this-in-production'
]);

/**
 * Fail fast in production when partner security env is misconfigured.
 */
function validatePartnerSecurityEnv() {
  if (process.env.NODE_ENV !== 'production') {
    return;
  }

  const errors = [];

  if (!process.env.ENCRYPTION_KEY || String(process.env.ENCRYPTION_KEY).length < 16) {
    errors.push('ENCRYPTION_KEY must be set on Render (min 16 characters).');
  }

  const pepper = process.env.PARTNER_AADHAAR_HASH_PEPPER || process.env.ENCRYPTION_KEY;
  if (!pepper || pepper === 'change-this-to-a-long-random-string') {
    errors.push(
      'PARTNER_AADHAAR_HASH_PEPPER must be set on Render (or use a strong ENCRYPTION_KEY as fallback).'
    );
  }

  const jwt = process.env.JWT_SECRET || '';
  if (!jwt || jwt.length < 32 || WEAK_JWT_SECRETS.has(jwt) || jwt.includes('change-this')) {
    errors.push(
      'JWT_SECRET must be set on Render to a random string (32+ chars), not the example placeholder.'
    );
  }

  if (errors.length > 0) {
    const banner = [
      '',
      '=== Startup blocked: fix these Render environment variables ===',
      ...errors.map((message) => `  • ${message}`),
      'Render → your service → Environment → add/update keys → Save → Manual Deploy',
      '================================================================',
      ''
    ].join('\n');

    console.error(banner);
    errors.forEach((message) => logger.error(`Security config: ${message}`));
    process.exit(1);
  }
}

module.exports = { validatePartnerSecurityEnv };

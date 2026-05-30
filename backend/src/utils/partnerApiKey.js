const crypto = require('crypto');

const KEY_PREFIX = 'ak_live_';

function generatePartnerApiKey(tenantSlug) {
  const slug = String(tenantSlug || 'tenant')
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, '')
    .slice(0, 32);
  const secret = crypto.randomBytes(24).toString('hex');
  const fullKey = `${KEY_PREFIX}${slug}_${secret}`;
  const keyPrefix = fullKey.slice(0, 20);
  const keyHash = hashApiKey(fullKey);
  return { fullKey, keyPrefix, keyHash };
}

function hashApiKey(apiKey) {
  return crypto.createHash('sha256').update(String(apiKey)).digest('hex');
}

function parseApiKeyFromRequest(req) {
  const auth = req.headers.authorization;
  if (auth && auth.startsWith('Bearer ')) {
    return auth.slice(7).trim();
  }
  if (req.headers['x-api-key']) {
    return String(req.headers['x-api-key']).trim();
  }
  return null;
}

module.exports = {
  KEY_PREFIX,
  generatePartnerApiKey,
  hashApiKey,
  parseApiKeyFromRequest
};

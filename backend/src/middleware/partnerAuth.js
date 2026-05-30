const Tenant = require('../models/Tenant');
const logger = require('../utils/logger');
const { parseApiKeyFromRequest, hashApiKey } = require('../utils/partnerApiKey');

async function authenticatePartner(req, res, next) {
  try {
    const apiKey = parseApiKeyFromRequest(req);
    if (!apiKey || !apiKey.startsWith('ak_live_')) {
      return res.status(401).json({
        success: false,
        message: 'Missing or invalid API key. Use Authorization: Bearer <api_key> or X-API-Key header.'
      });
    }

    const keyPrefix = apiKey.slice(0, 20);
    const tenant = await Tenant.findOne({ apiKeyPrefix: keyPrefix, isActive: true }).select('+apiKeyHash');

    if (!tenant) {
      return res.status(401).json({
        success: false,
        message: 'Invalid API key'
      });
    }

    const keyHash = hashApiKey(apiKey);
    if (keyHash !== tenant.apiKeyHash) {
      logger.warn('Partner API key hash mismatch', { tenantId: tenant.tenantId, keyPrefix });
      return res.status(401).json({
        success: false,
        message: 'Invalid API key'
      });
    }

    req.tenant = {
      _id: tenant._id,
      tenantId: tenant.tenantId,
      name: tenant.name,
      rateLimitPerMinute: tenant.rateLimitPerMinute
    };

    next();
  } catch (error) {
    logger.error('Partner authentication error:', error);
    return res.status(500).json({
      success: false,
      message: 'Authentication failed'
    });
  }
}

module.exports = { authenticatePartner };

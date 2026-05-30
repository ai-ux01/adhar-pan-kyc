const jwt = require('jsonwebtoken');
const Tenant = require('../models/Tenant');
const logger = require('../utils/logger');
const { parseApiKeyFromRequest, hashApiKey } = require('../utils/partnerApiKey');

async function authenticateWithApiKey(req, res, apiKey) {
  if (!apiKey || !apiKey.startsWith('ak_live_')) {
    return false;
  }

  const keyPrefix = apiKey.slice(0, 20);
  const tenant = await Tenant.findOne({ apiKeyPrefix: keyPrefix, isActive: true }).select('+apiKeyHash');

  if (!tenant) {
    res.status(401).json({
      success: false,
      message: 'Invalid API key'
    });
    return true;
  }

  const keyHash = hashApiKey(apiKey);
  if (keyHash !== tenant.apiKeyHash) {
    logger.warn('Partner API key hash mismatch', { tenantId: tenant.tenantId, keyPrefix });
    res.status(401).json({
      success: false,
      message: 'Invalid API key'
    });
    return true;
  }

  req.tenant = {
    _id: tenant._id,
    tenantId: tenant.tenantId,
    name: tenant.name,
    rateLimitPerMinute: tenant.rateLimitPerMinute
  };

  return true;
}

async function authenticateWithPartnerJwt(req, res, token) {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.type !== 'partner' || !decoded.id) {
      return false;
    }

    const tenant = await Tenant.findOne({ _id: decoded.id, isActive: true });
    if (!tenant) {
      res.status(401).json({
        success: false,
        message: 'Invalid or inactive tenant session'
      });
      return true;
    }

    if ((decoded.sessionVersion || 1) !== (tenant.portalSessionVersion || 1)) {
      res.status(401).json({
        success: false,
        message: 'Session expired. Please log in again.'
      });
      return true;
    }

    req.tenant = {
      _id: tenant._id,
      tenantId: tenant.tenantId,
      name: tenant.name,
      rateLimitPerMinute: tenant.rateLimitPerMinute
    };

    return true;
  } catch (error) {
    return false;
  }
}

async function authenticatePartner(req, res, next) {
  try {
    const apiKey = parseApiKeyFromRequest(req);
    if (apiKey) {
      const handled = await authenticateWithApiKey(req, res, apiKey);
      if (handled) {
        if (req.tenant) return next();
        return;
      }
    }

    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.split(' ')[1];
      if (token && !token.startsWith('ak_live_')) {
        const handled = await authenticateWithPartnerJwt(req, res, token);
        if (handled) {
          if (req.tenant) return next();
          return;
        }
      }
    }

    return res.status(401).json({
      success: false,
      message: 'Missing or invalid credentials. Use API key or partner portal login token.'
    });
  } catch (error) {
    logger.error('Partner authentication error:', error);
    return res.status(500).json({
      success: false,
      message: 'Authentication failed'
    });
  }
}

module.exports = { authenticatePartner };

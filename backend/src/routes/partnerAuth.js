const express = require('express');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Tenant = require('../models/Tenant');
const logger = require('../utils/logger');

const router = express.Router();

const partnerLoginIpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many login attempts from this IP. Try again in 15 minutes.'
  }
});

const partnerLoginEmailLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => String(req.body?.email || '').trim().toLowerCase() || req.ip,
  message: {
    success: false,
    message: 'Too many login attempts for this account. Try again in 15 minutes.'
  }
});

function signPartnerToken(tenant) {
  return jwt.sign(
    {
      type: 'partner',
      id: tenant._id.toString(),
      tenantId: tenant.tenantId,
      sessionVersion: tenant.portalSessionVersion || 1
    },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
}

/**
 * POST /api/partner-auth/login
 * Tenant portal login (email + password).
 */
router.post('/login', partnerLoginIpLimiter, partnerLoginEmailLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    const tenant = await Tenant.findOne({
      portalEmail: String(email).trim().toLowerCase(),
      isActive: true
    }).select('+passwordHash');

    if (!tenant || !tenant.passwordHash) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    const isMatch = await bcrypt.compare(password, tenant.passwordHash);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    const token = signPartnerToken(tenant);

    res.json({
      success: true,
      message: 'Login successful',
      token,
      tenant: {
        tenantId: tenant.tenantId,
        name: tenant.name,
        contactEmail: tenant.contactEmail,
        portalEmail: tenant.portalEmail
      }
    });
  } catch (error) {
    logger.error('Partner portal login error:', error);
    res.status(500).json({
      success: false,
      message: 'Login failed'
    });
  }
});

/**
 * GET /api/partner-auth/me
 */
router.get('/me', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, message: 'Not authorized' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.type !== 'partner') {
      return res.status(401).json({ success: false, message: 'Invalid partner token' });
    }

    const tenant = await Tenant.findById(decoded.id).select('-apiKeyHash -passwordHash');
    if (!tenant || !tenant.isActive) {
      return res.status(401).json({ success: false, message: 'Tenant not found or inactive' });
    }

    if ((decoded.sessionVersion || 1) !== (tenant.portalSessionVersion || 1)) {
      return res.status(401).json({
        success: false,
        message: 'Session expired. Please log in again.'
      });
    }

    res.json({
      success: true,
      tenant: {
        tenantId: tenant.tenantId,
        name: tenant.name,
        contactEmail: tenant.contactEmail,
        portalEmail: tenant.portalEmail,
        rateLimitPerMinute: tenant.rateLimitPerMinute
      }
    });
  } catch (error) {
    logger.error('Partner portal me error:', error);
    res.status(401).json({ success: false, message: 'Not authorized' });
  }
});

module.exports = router;

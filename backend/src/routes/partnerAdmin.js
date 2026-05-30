const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const router = express.Router();
const { protect, authorize } = require('../middleware/auth');
const Tenant = require('../models/Tenant');
const { generatePartnerApiKey } = require('../utils/partnerApiKey');
const { listTenantVerifications } = require('../services/partnerAadhaarService');
const logger = require('../utils/logger');

function generatePortalPassword() {
  return crypto.randomBytes(9).toString('base64url').slice(0, 12);
}

async function hashPortalPassword(password) {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
}

/**
 * POST /api/admin/partners
 * Create tenant and return API key once.
 */
router.post('/', protect, authorize('admin'), async (req, res) => {
  try {
    const { tenantId, name, contactEmail, rateLimitPerMinute, metadata, portalEmail, portalPassword } = req.body;

    if (!tenantId || !name) {
      return res.status(400).json({
        success: false,
        message: 'tenantId and name are required'
      });
    }

    if (!portalEmail) {
      return res.status(400).json({
        success: false,
        message: 'portalEmail is required for tenant portal login'
      });
    }

    const normalizedPortalEmail = String(portalEmail).trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedPortalEmail)) {
      return res.status(400).json({
        success: false,
        message: 'Valid portalEmail is required'
      });
    }

    const existingEmail = await Tenant.findOne({ portalEmail: normalizedPortalEmail });
    if (existingEmail) {
      return res.status(409).json({
        success: false,
        message: 'portalEmail is already in use'
      });
    }

    const plainPortalPassword = portalPassword ? String(portalPassword) : generatePortalPassword();
    if (plainPortalPassword.length < 8) {
      return res.status(400).json({
        success: false,
        message: 'portalPassword must be at least 8 characters'
      });
    }

    const slug = String(tenantId).trim().toLowerCase();
    if (!/^[a-z0-9_-]{3,64}$/.test(slug)) {
      return res.status(400).json({
        success: false,
        message: 'tenantId must be 3-64 chars: lowercase letters, numbers, _ or -'
      });
    }

    const existing = await Tenant.findOne({ tenantId: slug });
    if (existing) {
      return res.status(409).json({
        success: false,
        message: 'tenantId already exists'
      });
    }

    const { fullKey, keyPrefix, keyHash } = generatePartnerApiKey(slug);

    const tenant = await Tenant.create({
      tenantId: slug,
      name: String(name).trim(),
      apiKeyPrefix: keyPrefix,
      apiKeyHash: keyHash,
      contactEmail: contactEmail || '',
      portalEmail: normalizedPortalEmail,
      passwordHash: await hashPortalPassword(plainPortalPassword),
      rateLimitPerMinute: rateLimitPerMinute || 60,
      metadata: metadata || {}
    });

    res.status(201).json({
      success: true,
      message: 'Partner tenant created. Store the API key and portal password securely; they will not be shown again.',
      data: {
        id: tenant._id,
        tenantId: tenant.tenantId,
        name: tenant.name,
        apiKey: fullKey,
        apiKeyPrefix: keyPrefix,
        portalEmail: tenant.portalEmail,
        portalPassword: plainPortalPassword,
        isActive: tenant.isActive,
        rateLimitPerMinute: tenant.rateLimitPerMinute
      }
    });
  } catch (error) {
    logger.error('Create partner tenant error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to create partner tenant'
    });
  }
});

/**
 * GET /api/admin/partners
 */
router.get('/', protect, authorize('admin'), async (req, res) => {
  try {
    const tenants = await Tenant.find()
      .select('-apiKeyHash')
      .sort({ createdAt: -1 })
      .lean();

    res.json({
      success: true,
      data: tenants
    });
  } catch (error) {
    logger.error('List partners error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to list partner tenants'
    });
  }
});

/**
 * PATCH /api/admin/partners/:tenantId
 * Activate/deactivate or update limits.
 */
router.patch('/:tenantId', protect, authorize('admin'), async (req, res) => {
  try {
    const { isActive, name, rateLimitPerMinute, contactEmail } = req.body;
    const tenant = await Tenant.findOne({ tenantId: req.params.tenantId.toLowerCase() });

    if (!tenant) {
      return res.status(404).json({
        success: false,
        message: 'Partner tenant not found'
      });
    }

    if (typeof isActive === 'boolean') tenant.isActive = isActive;
    if (name) tenant.name = String(name).trim();
    if (rateLimitPerMinute) tenant.rateLimitPerMinute = rateLimitPerMinute;
    if (contactEmail !== undefined) tenant.contactEmail = contactEmail;

    await tenant.save();

    res.json({
      success: true,
      message: 'Partner tenant updated',
      data: {
        id: tenant._id,
        tenantId: tenant.tenantId,
        name: tenant.name,
        isActive: tenant.isActive,
        rateLimitPerMinute: tenant.rateLimitPerMinute
      }
    });
  } catch (error) {
    logger.error('Update partner tenant error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update partner tenant'
    });
  }
});

/**
 * POST /api/admin/partners/:tenantId/rotate-key
 * Issue new API key (invalidates old key).
 */
router.post('/:tenantId/rotate-key', protect, authorize('admin'), async (req, res) => {
  try {
    const tenant = await Tenant.findOne({ tenantId: req.params.tenantId.toLowerCase() }).select('+apiKeyHash');

    if (!tenant) {
      return res.status(404).json({
        success: false,
        message: 'Partner tenant not found'
      });
    }

    const { fullKey, keyPrefix, keyHash } = generatePartnerApiKey(tenant.tenantId);
    tenant.apiKeyPrefix = keyPrefix;
    tenant.apiKeyHash = keyHash;
    await tenant.save();

    res.json({
      success: true,
      message: 'API key rotated. Store the new key securely; it will not be shown again.',
      data: {
        tenantId: tenant.tenantId,
        apiKey: fullKey,
        apiKeyPrefix: keyPrefix
      }
    });
  } catch (error) {
    logger.error('Rotate partner key error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to rotate API key'
    });
  }
});

/**
 * GET /api/admin/partners/:tenantId/verifications
 */
router.get('/:tenantId/verifications', protect, authorize('admin'), async (req, res) => {
  try {
    const tenant = await Tenant.findOne({ tenantId: req.params.tenantId.toLowerCase() });
    if (!tenant) {
      return res.status(404).json({
        success: false,
        message: 'Partner tenant not found'
      });
    }

    const result = await listTenantVerifications(
      {
        _id: tenant._id,
        tenantId: tenant.tenantId,
        name: tenant.name,
        rateLimitPerMinute: tenant.rateLimitPerMinute
      },
      req.query
    );

    res.json(result);
  } catch (error) {
    logger.error('Admin list tenant verifications error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to list tenant verifications'
    });
  }
});

/**
 * POST /api/admin/partners/:tenantId/reset-portal-password
 */
router.post('/:tenantId/reset-portal-password', protect, authorize('admin'), async (req, res) => {
  try {
    const tenant = await Tenant.findOne({ tenantId: req.params.tenantId.toLowerCase() }).select('+passwordHash');

    if (!tenant) {
      return res.status(404).json({
        success: false,
        message: 'Partner tenant not found'
      });
    }

    if (!tenant.portalEmail) {
      return res.status(400).json({
        success: false,
        message: 'Tenant has no portal login. Set portalEmail first.'
      });
    }

    const plainPortalPassword = req.body.portalPassword
      ? String(req.body.portalPassword)
      : generatePortalPassword();

    if (plainPortalPassword.length < 8) {
      return res.status(400).json({
        success: false,
        message: 'portalPassword must be at least 8 characters'
      });
    }

    tenant.passwordHash = await hashPortalPassword(plainPortalPassword);
    tenant.portalSessionVersion = (tenant.portalSessionVersion || 1) + 1;
    await tenant.save();

    res.json({
      success: true,
      message: 'Portal password reset. Share it securely; it will not be shown again.',
      data: {
        tenantId: tenant.tenantId,
        portalEmail: tenant.portalEmail,
        portalPassword: plainPortalPassword
      }
    });
  } catch (error) {
    logger.error('Reset partner portal password error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reset portal password'
    });
  }
});

module.exports = router;

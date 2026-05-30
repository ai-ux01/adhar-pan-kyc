const express = require('express');
const rateLimit = require('express-rate-limit');
const { authenticatePartner } = require('../middleware/partnerAuth');
const { isValidAadhaar, normalizeAadhaar } = require('../utils/aadhaarHash');
const {
  partnerAadhaarEntry,
  partnerSendOtp,
  partnerVerifyOtp,
  getVerificationById
} = require('../services/partnerAadhaarService');
const { logEvent } = require('../services/auditService');
const logger = require('../utils/logger');

const router = express.Router();

const partnerRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: (req) => req.tenant?.rateLimitPerMinute || 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.tenant?.tenantId || req.ip,
  message: {
    success: false,
    message: 'Rate limit exceeded. Try again later.'
  }
});

router.use(authenticatePartner);
router.use(partnerRateLimiter);

function validateConsent(consent) {
  return consent === true || consent === 'true' || consent === 'y' || consent === 'Y';
}

async function auditPartnerCall(req, action, details = {}) {
  try {
    await logEvent({
      userId: null,
      action,
      module: 'partner_aadhaar',
      resource: 'tenant',
      resourceId: req.tenant?._id,
      details: {
        tenantId: req.tenant?.tenantId,
        ...details
      },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });
  } catch (e) {
    logger.warn('Partner audit log failed:', e.message);
  }
}

/**
 * GET /api/v1/partner/me
 * Validate API key or partner JWT and return tenant info.
 */
router.get('/me', (req, res) => {
  res.json({
    success: true,
    tenant: {
      tenantId: req.tenant.tenantId,
      name: req.tenant.name,
      rateLimitPerMinute: req.tenant.rateLimitPerMinute
    }
  });
});

/**
 * POST /api/v1/partner/aadhaar/entry
 * Check tenant cache for prior successful verification.
 */
router.post('/aadhaar/entry', async (req, res) => {
  try {
    const { aadhaarNumber, consent, externalReferenceId } = req.body;

    if (!aadhaarNumber || !isValidAadhaar(aadhaarNumber)) {
      return res.status(400).json({
        success: false,
        message: 'Valid 12-digit aadhaarNumber is required'
      });
    }

    const result = await partnerAadhaarEntry(req.tenant, {
      aadhaarNumber,
      consent: validateConsent(consent),
      externalReferenceId
    });

    await auditPartnerCall(req, 'partner_aadhaar_entry', {
      cached: result.cached,
      aadhaarMasked: normalizeAadhaar(aadhaarNumber).slice(-4)
    });

    return res.json(result);
  } catch (error) {
    logger.error('Partner aadhaar entry error:', error);
    return res.status(error.statusCode || 500).json({
      success: false,
      message: error.message || 'Entry failed'
    });
  }
});

/**
 * POST /api/v1/partner/aadhaar/otp/send
 */
router.post('/aadhaar/otp/send', async (req, res) => {
  try {
    const { aadhaarNumber, consent, externalReferenceId, reason } = req.body;

    if (!aadhaarNumber || !isValidAadhaar(aadhaarNumber)) {
      return res.status(400).json({
        success: false,
        message: 'Valid 12-digit aadhaarNumber is required'
      });
    }

    const result = await partnerSendOtp(req.tenant, {
      aadhaarNumber,
      consent: validateConsent(consent),
      externalReferenceId,
      reason
    });

    await auditPartnerCall(req, 'partner_aadhaar_otp_send', {
      cached: result.cached,
      otpSent: result.otpSent
    });

    return res.json(result);
  } catch (error) {
    logger.error('Partner OTP send error:', error);
    return res.status(error.statusCode || 500).json({
      success: false,
      message: error.message || 'Failed to send OTP'
    });
  }
});

/**
 * POST /api/v1/partner/aadhaar/otp/verify
 */
router.post('/aadhaar/otp/verify', async (req, res) => {
  try {
    const { aadhaarNumber, otp, transactionId, externalReferenceId } = req.body;

    if (!aadhaarNumber || !otp || !transactionId) {
      return res.status(400).json({
        success: false,
        message: 'aadhaarNumber, otp, and transactionId are required'
      });
    }

    if (!isValidAadhaar(aadhaarNumber)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid Aadhaar number format'
      });
    }

    if (!/^\d{6}$/.test(String(otp))) {
      return res.status(400).json({
        success: false,
        message: 'OTP must be 6 digits'
      });
    }

    const result = await partnerVerifyOtp(req.tenant, {
      aadhaarNumber,
      otp: String(otp),
      transactionId,
      externalReferenceId
    });

    await auditPartnerCall(req, 'partner_aadhaar_otp_verify', {
      success: result.success,
      cached: result.cached,
      verificationId: result.data?.verificationId
    });

    return res.json(result);
  } catch (error) {
    logger.error('Partner OTP verify error:', error);
    return res.status(error.statusCode || 500).json({
      success: false,
      message: error.message || 'Failed to verify OTP'
    });
  }
});

/**
 * GET /api/v1/partner/aadhaar/verification/:verificationId
 */
router.get('/aadhaar/verification/:verificationId', async (req, res) => {
  try {
    const result = await getVerificationById(req.tenant, req.params.verificationId);
    return res.json(result);
  } catch (error) {
    return res.status(error.statusCode || 500).json({
      success: false,
      message: error.message || 'Failed to fetch verification'
    });
  }
});

module.exports = router;

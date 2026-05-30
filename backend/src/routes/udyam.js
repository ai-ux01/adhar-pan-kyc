const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/auth');
const UdyamVerification = require('../models/UdyamVerification');
const {
  verifyUdyamRegistration,
  normalizeUdyamNumber,
  isValidUdyamFormat,
  generateVerificationId,
} = require('../services/udyamVerificationService');
const { consumeCredits, sendCreditsError } = require('../utils/creditsHelper');
const { logEvent } = require('../services/auditService');
const logger = require('../utils/logger');

async function logUdyamEvent(action, userId, details, req) {
  return logEvent({
    userId,
    action,
    module: 'udyam',
    resource: 'udyam_record',
    resourceId: details.recordId,
    details,
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
  });
}

router.post('/verify-single', protect, async (req, res) => {
  try {
    const { udyamNumber, verificationId: clientVerificationId } = req.body;

    if (!udyamNumber) {
      return res.status(400).json({
        success: false,
        message: 'Udyam registration number is required',
      });
    }

    const normalized = normalizeUdyamNumber(udyamNumber);
    if (!isValidUdyamFormat(normalized)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid Udyam format. Expected format: UDYAM-XX-00-1234567',
      });
    }

    let creditResult;
    try {
      creditResult = await consumeCredits(req.user.id, 1);
    } catch (creditError) {
      return sendCreditsError(res, creditError);
    }

    const verificationId =
      clientVerificationId && String(clientVerificationId).trim().length <= 50
        ? String(clientVerificationId).trim()
        : generateVerificationId();

    const startTime = Date.now();
    let verificationResult;

    try {
      verificationResult = await verifyUdyamRegistration(normalized, verificationId);
    } catch (apiError) {
      const processingTime = Date.now() - startTime;
      const errorRecord = new UdyamVerification({
        userId: req.user.id,
        batchId: `UDYAM_${Date.now()}`,
        verificationId,
        udyamNumber: normalized,
        status: 'error',
        errorMessage: apiError.message,
        verificationDetails: {
          apiResponse: apiError.cashfreeResponse || null,
          source: 'cashfree',
          verificationDate: new Date(),
        },
        processingTime,
        isProcessed: true,
        processedAt: new Date(),
      });
      await errorRecord.save();

      await logUdyamEvent(
        'udyam_verification_failed',
        req.user.id,
        { recordId: errorRecord._id, udyamNumber: normalized, status: 'error' },
        req
      );

      return res.status(apiError.statusCode || 502).json({
        success: false,
        message: apiError.message || 'Failed to verify Udyam registration',
        data: {
          recordId: errorRecord._id,
          udyamNumber: normalized,
          status: 'error',
          creditsRemaining: creditResult?.remaining,
        },
      });
    }

    const processingTime = Date.now() - startTime;
    const record = new UdyamVerification({
      userId: req.user.id,
      batchId: `UDYAM_${Date.now()}`,
      verificationId: verificationResult.verificationId,
      udyamNumber: normalized,
      status: verificationResult.valid ? 'verified' : 'rejected',
      enterpriseName: verificationResult.details.enterpriseName,
      ownerName: verificationResult.details.ownerName,
      organizationType: verificationResult.details.organizationType,
      enterpriseType: verificationResult.details.enterpriseType,
      majorActivity: verificationResult.details.majorActivity,
      verificationDetails: {
        ...verificationResult.details,
        verificationDate: new Date(),
        remarks: verificationResult.message,
      },
      processingTime,
      isProcessed: true,
      processedAt: new Date(),
    });

    await record.save();

    await logUdyamEvent(
      'udyam_verification_completed',
      req.user.id,
      {
        recordId: record._id,
        udyamNumber: normalized,
        status: record.status,
        processingTime,
      },
      req
    );

    const apiData = verificationResult.details.apiResponse || {};

    res.json({
      success: true,
      message: verificationResult.message,
      data: {
        recordId: record._id,
        udyamNumber: record.udyamNumber,
        status: record.status,
        verificationId: record.verificationId,
        enterpriseName: record.enterpriseName,
        ownerName: record.ownerName,
        organizationType: record.organizationType,
        enterpriseType: record.enterpriseType,
        majorActivity: record.majorActivity,
        dateOfUdyamRegistration: apiData.date_of_udyam_registration,
        dateOfIncorporation: apiData.date_of_incorporation,
        gender: apiData.gender,
        socialCategory: apiData.social_category,
        splitAddress: apiData.split_address,
        unitLocations: apiData.unit_locations,
        nicCodes: apiData.nic_codes,
        classificationHistory: apiData.classification_history,
        udyamCertificateUrl: apiData.udyam_certificate_url,
        dic: apiData.dic,
        msmeDi: apiData.msme_di,
        referenceId: apiData.reference_id,
        verificationDetails: record.verificationDetails,
        processedAt: record.processedAt,
        processingTime: record.processingTime,
        creditsRemaining: creditResult?.remaining,
      },
    });
  } catch (error) {
    if (error.statusCode === 402) {
      return sendCreditsError(res, error);
    }
    logger.error('Error in Udyam verification:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to verify Udyam registration',
    });
  }
});

router.get('/records', protect, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (Number(page) - 1) * Number(limit);

    const [records, total] = await Promise.all([
      UdyamVerification.find({ userId: req.user.id })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(Number(limit))
        .select('-verificationDetails.apiResponse'),
      UdyamVerification.countDocuments({ userId: req.user.id }),
    ]);

    res.json({
      success: true,
      data: {
        records,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      },
    });
  } catch (error) {
    logger.error('Error fetching Udyam records:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch Udyam verification records',
    });
  }
});

module.exports = router;

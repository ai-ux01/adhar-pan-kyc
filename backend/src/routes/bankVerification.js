const express = require('express');
const router = express.Router();
const { protect, checkModuleAccess } = require('../middleware/auth');
const BankVerification = require('../models/BankVerification');
const { verifyBankAccount } = require('../services/bankVerificationService');
const { consumeCredits, sendCreditsError } = require('../utils/creditsHelper');
const { logEvent } = require('../services/auditService');
const logger = require('../utils/logger');

async function logBankEvent(action, userId, details, req) {
  return logEvent({
    userId,
    action,
    module: 'bank-verification',
    resource: 'bank_record',
    resourceId: details.recordId,
    details,
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
  });
}

// @route   POST /api/bank-verification/verify-single
// @desc    Verify a single bank account (Penny-Less)
// @access  Private
router.post('/verify-single', protect, checkModuleAccess('bank-verification'), async (req, res) => {
  try {
    const { ifsc, accountNumber } = req.body;

    if (!ifsc || !accountNumber) {
      return res.status(400).json({
        success: false,
        message: 'IFSC and Account Number are required',
      });
    }

    const normalizedIfsc = String(ifsc).trim().toUpperCase();
    const normalizedAccount = String(accountNumber).trim();

    // Basic IFSC validation (11 characters)
    if (normalizedIfsc.length !== 11) {
      return res.status(400).json({
        success: false,
        message: 'Invalid IFSC code format. IFSC must be 11 characters long.',
      });
    }

    // Basic Account Number validation
    if (normalizedAccount.length < 8 || normalizedAccount.length > 20) {
      return res.status(400).json({
        success: false,
        message: 'Invalid Account Number. Must be between 8 and 20 digits.',
      });
    }

    let creditResult;
    try {
      creditResult = await consumeCredits(req.user.id, 1);
    } catch (creditError) {
      return sendCreditsError(res, creditError);
    }

    const startTime = Date.now();
    let verificationResult;

    try {
      verificationResult = await verifyBankAccount(normalizedIfsc, normalizedAccount);
    } catch (apiError) {
      const processingTime = Date.now() - startTime;
      const errorRecord = new BankVerification({
        userId: req.user.id,
        batchId: `BANK_${Date.now()}`,
        verificationId: `err_${Date.now()}`,
        ifsc: normalizedIfsc,
        accountNumber: normalizedAccount,
        status: 'error',
        errorMessage: apiError.message,
        verificationDetails: {
          apiResponse: apiError.sandboxResponse || null,
          source: 'sandbox',
          verificationDate: new Date(),
        },
        processingTime,
        isProcessed: true,
        processedAt: new Date(),
      });
      await errorRecord.save();

      await logBankEvent(
        'bank_verification_failed',
        req.user.id,
        { recordId: errorRecord._id, ifsc: normalizedIfsc, status: 'error' },
        req
      );

      return res.status(apiError.statusCode || 502).json({
        success: false,
        message: apiError.message || 'Failed to verify bank account',
        data: {
          recordId: errorRecord._id,
          ifsc: normalizedIfsc,
          status: 'error',
          creditsRemaining: creditResult?.remaining,
        },
      });
    }

    const processingTime = Date.now() - startTime;
    const record = new BankVerification({
      userId: req.user.id,
      batchId: `BANK_${Date.now()}`,
      verificationId: verificationResult.verificationId,
      ifsc: normalizedIfsc,
      accountNumber: normalizedAccount,
      status: verificationResult.valid ? 'verified' : 'rejected',
      nameAtBank: verificationResult.details.nameAtBank,
      accountExists: verificationResult.details.accountExists,
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

    await logBankEvent(
      'bank_verification_completed',
      req.user.id,
      {
        recordId: record._id,
        ifsc: normalizedIfsc,
        status: record.status,
        processingTime,
      },
      req
    );

    // Decrypt the record fields for response
    const decryptedRecord = record.decryptData();

    res.json({
      success: true,
      message: verificationResult.message,
      data: {
        recordId: record._id,
        ifsc: decryptedRecord.ifsc,
        accountNumber: decryptedRecord.accountNumber,
        status: record.status,
        verificationId: record.verificationId,
        nameAtBank: decryptedRecord.nameAtBank,
        accountExists: record.accountExists,
        processedAt: record.processedAt,
        processingTime: record.processingTime,
        creditsRemaining: creditResult?.remaining,
      },
    });
  } catch (error) {
    if (error.statusCode === 402) {
      return sendCreditsError(res, error);
    }
    logger.error('Error in Bank verification route:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to verify bank account',
    });
  }
});

// @route   GET /api/bank-verification/records
// @desc    Get bank verification records for logged in user
// @access  Private
router.get('/records', protect, checkModuleAccess('bank-verification'), async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (Number(page) - 1) * Number(limit);

    const [records, total] = await Promise.all([
      BankVerification.find({ userId: req.user.id })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(Number(limit)),
      BankVerification.countDocuments({ userId: req.user.id }),
    ]);

    // Decrypt records before returning to client
    const decryptedRecords = records.map(record => {
      const decrypted = record.decryptData();
      // Mask account number for security on response list
      if (decrypted.accountNumber && decrypted.accountNumber.length > 4) {
        const len = decrypted.accountNumber.length;
        decrypted.accountNumber = 'X'.repeat(len - 4) + decrypted.accountNumber.slice(-4);
      }
      // Remove raw api response from list query for performance/security
      if (decrypted.verificationDetails) {
        delete decrypted.verificationDetails.apiResponse;
      }
      return decrypted;
    });

    res.json({
      success: true,
      data: {
        records: decryptedRecords,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      },
    });
  } catch (error) {
    logger.error('Error fetching Bank records:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch bank verification records',
    });
  }
});

module.exports = router;

const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const multer = require('multer');
const XLSX = require('xlsx');
const fs = require('fs');
const path = require('path');
const { protect, checkModuleAccess } = require('../middleware/auth');
const BankVerification = require('../models/BankVerification');
const { verifyBankAccount } = require('../services/bankVerificationService');
const { consumeCredits, sendCreditsError } = require('../utils/creditsHelper');
const { logEvent } = require('../services/auditService');
const { resolveUploadedColumnKey } = require('../utils/excelUploadColumns');
const logger = require('../utils/logger');

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '../../uploads/bank-verification');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});

const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['.xlsx', '.xls', '.csv'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedTypes.includes(ext)) {
      return cb(null, true);
    }
    cb(new Error('Only Excel (.xlsx, .xls) and CSV (.csv) files are allowed'));
  },
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

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

// @route   POST /api/bank-verification/upload
// @desc    Upload Bank details Excel file
// @access  Private
router.post('/upload', protect, checkModuleAccess('bank-verification'), upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No file uploaded'
      });
    }

    const workbook = XLSX.readFile(req.file.path);
    const sheetName = workbook.SheetNames[0];
    const worksheet = workbook.Sheets[sheetName];
    const data = XLSX.utils.sheet_to_json(worksheet);

    if (data.length === 0) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({
        success: false,
        message: 'No data found in the Excel file'
      });
    }

    // Validate required columns
    const requiredColumns = ['ifsc', 'accountNumber'];
    const firstRow = data[0];
    
    const columnMapping = {
      'ifsc': ['ifsc', 'IFSC', 'IFSC Code', 'ifsc_code', 'IFSC_CODE', 'ifscCode', 'Ifsc', 'Branch IFSC'],
      'accountNumber': ['accountNumber', 'Account Number', 'Account No', 'Account_No', 'account_number', 'accountNumber', 'account', 'AccountNumber', 'accountNo']
    };
    
    const missingColumns = [];
    const columnMap = {};

    requiredColumns.forEach((requiredCol) => {
      const possibleNames = columnMapping[requiredCol];
      const matchedKey = resolveUploadedColumnKey(firstRow, possibleNames);
      if (matchedKey) {
        columnMap[requiredCol] = matchedKey;
      } else {
        missingColumns.push(requiredCol);
      }
    });

    if (missingColumns.length > 0) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({
        success: false,
        message: `Missing required columns: ${missingColumns.join(', ')}`,
        debug: {
          foundColumns: Object.keys(firstRow),
          requiredColumns,
          columnMapping
        }
      });
    }

    // Create batch ID
    const batchId = `BATCH_BANK_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    
    // Process and save records
    const records = [];
    for (const row of data) {
      const ifscVal = row[columnMap.ifsc];
      const accountVal = row[columnMap.accountNumber];
      
      // Skip rows with missing or empty fields
      if (!ifscVal || !accountVal || ifscVal.toString().trim() === '' || accountVal.toString().trim() === '') {
        continue;
      }
      
      const record = new BankVerification({
        userId: req.user.id,
        batchId: batchId,
        ifsc: ifscVal.toString().trim().toUpperCase(),
        accountNumber: accountVal.toString().trim(),
        status: 'pending'
      });
      
      await record.save();
      records.push(record);
    }

    // Clean up uploaded file
    fs.unlinkSync(req.file.path);

    if (records.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No valid records found in the file.'
      });
    }

    // Log successful upload
    logger.info(`Successfully uploaded Bank verification file: ${req.file.originalname}`, {
      userId: req.user.id,
      batchId,
      totalRecords: records.length,
    });

    await logBankEvent('bank_verification_upload', req.user.id, {
      batchId,
      recordCount: records.length,
      fileName: req.file.originalname
    }, req);

    res.json({
      success: true,
      message: `Successfully uploaded ${records.length} records`,
      data: {
        batchId,
        totalRecords: records.length,
        totalRows: data.length,
        skippedRows: data.length - records.length,
        batchName: req.file.originalname
      }
    });

  } catch (error) {
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    logger.error('Error uploading Bank file:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to upload file',
      error: error.message
    });
  }
});

// @route   GET /api/bank-verification/batches
// @desc    Get all Bank verification batches for the user
// @access  Private
router.get('/batches', protect, checkModuleAccess('bank-verification'), async (req, res) => {
  try {
    const batches = await BankVerification.aggregate([
      { 
        $match: { 
          userId: new mongoose.Types.ObjectId(req.user.id),
          // Exclude single verification records (start with BANK_)
          batchId: { $not: { $regex: /^BANK_/ } }
        } 
      },
      {
        $group: {
          _id: '$batchId',
          totalRecords: { $sum: 1 },
          pendingRecords: { $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] } },
          verifiedRecords: { $sum: { $cond: [{ $eq: ['$status', 'verified'] }, 1, 0] } },
          rejectedRecords: { $sum: { $cond: [{ $eq: ['$status', 'rejected'] }, 1, 0] } },
          errorRecords: { $sum: { $cond: [{ $eq: ['$status', 'error'] }, 1, 0] } },
          createdAt: { $first: '$createdAt' },
          updatedAt: { $first: '$updatedAt' }
        }
      },
      { $sort: { createdAt: -1 } }
    ]);

    res.json({ success: true, data: batches });
  } catch (error) {
    logger.error('Error fetching Bank batches:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch batches' });
  }
});

// @route   GET /api/bank-verification/batch/:batchId
// @desc    Get records for a specific batch
// @access  Private
router.get('/batch/:batchId', protect, checkModuleAccess('bank-verification'), async (req, res) => {
  try {
    const { batchId } = req.params;
    const records = await BankVerification.find({
      userId: req.user.id,
      batchId: batchId
    }).sort({ createdAt: -1 });

    if (records.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Batch not found'
      });
    }

    // Decrypt sensitive data for display
    const decryptedRecords = records.map(record => {
      try {
        const tempDoc = new BankVerification(record);
        return tempDoc.decryptData();
      } catch (error) {
        logger.error('Error decrypting record:', error);
        return record;
      }
    });

    const stats = await BankVerification.aggregate([
      { $match: { userId: new mongoose.Types.ObjectId(req.user.id), batchId } },
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 }
        }
      }
    ]);

    const statusCounts = {
      total: records.length,
      pending: 0,
      verified: 0,
      rejected: 0,
      error: 0
    };

    stats.forEach(stat => {
      statusCounts[stat._id] = stat.count;
    });

    res.json({
      success: true,
      data: {
        batchId,
        records: decryptedRecords,
        stats: statusCounts
      }
    });
  } catch (error) {
    logger.error('Error fetching batch details:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch batch details' });
  }
});

// @route   POST /api/bank-verification/batch/:batchId/process
// @desc    Process pending records in a batch
// @access  Private
router.post('/batch/:batchId/process', protect, checkModuleAccess('bank-verification'), async (req, res) => {
  try {
    const { batchId } = req.params;
    
    // Get pending records
    const pendingRecords = await BankVerification.find({
      userId: req.user.id,
      batchId: batchId,
      status: 'pending'
    });

    if (pendingRecords.length === 0) {
      return res.json({
        success: true,
        message: 'No pending records to process'
      });
    }

    const results = [];

    for (const record of pendingRecords) {
      try {
        let creditResult;
        try {
          creditResult = await consumeCredits(req.user.id, 1);
        } catch (creditError) {
          results.push({
            recordId: record._id,
            status: 'error',
            error: creditError.message,
            code: creditError.code,
          });
          break;
        }

        const startTime = Date.now();
        
        // Decrypt the data before calling the API
        const decryptedRecord = record.decryptData();
        
        const verificationResult = await verifyBankAccount(decryptedRecord.ifsc, decryptedRecord.accountNumber);
        
        const processingTime = Date.now() - startTime;
        
        record.status = verificationResult.valid ? 'verified' : 'rejected';
        record.nameAtBank = verificationResult.details.nameAtBank;
        record.accountExists = verificationResult.details.accountExists;
        record.isProcessed = true;
        record.processedAt = new Date();
        record.processingTime = processingTime;
        record.verificationDetails = {
          ...verificationResult.details,
          verificationDate: new Date(),
          remarks: verificationResult.message
        };
        
        await record.save();
        
        results.push({
          recordId: record._id,
          status: record.status,
          processingTime: processingTime
        });

        await logBankEvent('bank_verification_run', req.user.id, {
          recordId: record._id,
          batchId: batchId,
          status: record.status,
          processingTime: processingTime
        }, req);

        // Delay between API calls to avoid rate limiting
        await new Promise(resolve => setTimeout(resolve, 1000));

      } catch (error) {
        logger.error(`Error processing record ${record._id}:`, error);
        
        record.status = 'error';
        record.errorMessage = error.message;
        record.isProcessed = true;
        record.processedAt = new Date();
        await record.save();
        
        results.push({
          recordId: record._id,
          status: 'error',
          error: error.message
        });
      }
    }

    res.json({
      success: true,
      message: `Processed ${results.length} records`,
      data: {
        batchId,
        results,
        summary: {
          total: results.length,
          verified: results.filter(r => r.status === 'verified').length,
          rejected: results.filter(r => r.status === 'rejected').length,
          error: results.filter(r => r.status === 'error').length
        }
      }
    });

  } catch (error) {
    logger.error('Error processing batch:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to process batch',
      error: error.message
    });
  }
});

// @route   DELETE /api/bank-verification/batch/:batchId
// @desc    Delete batch and all its records
// @access  Private
router.delete('/batch/:batchId', protect, checkModuleAccess('bank-verification'), async (req, res) => {
  try {
    const { batchId } = req.params;
    
    if (batchId.startsWith('BANK_')) {
      return res.status(400).json({
        success: false,
        message: 'Cannot delete single verification records'
      });
    }
    
    const records = await BankVerification.find({
      userId: new mongoose.Types.ObjectId(req.user.id),
      batchId: batchId
    });

    if (records.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Batch not found or access denied'
      });
    }

    const deleteResult = await BankVerification.deleteMany({
      userId: new mongoose.Types.ObjectId(req.user.id),
      batchId: batchId
    });

    await logBankEvent('bank_batch_deleted', req.user.id, {
      batchId,
      recordCount: records.length
    }, req);

    res.json({
      success: true,
      message: `Successfully deleted batch with ${deleteResult.deletedCount} records`,
      data: {
        batchId,
        deletedRecords: deleteResult.deletedCount
      }
    });

  } catch (error) {
    logger.error('Error deleting batch:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete batch'
    });
  }
});

// @route   GET /api/bank-verification/records
// @desc    Get bank verification records for logged in user
// @access  Private
router.get('/records', protect, checkModuleAccess('bank-verification'), async (req, res) => {
  try {
    const isExport = req.query.export === '1' || req.query.export === 'true';
    const page = isExport ? 1 : Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = isExport ? 200 : Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
    const skip = isExport ? 0 : (page - 1) * limit;

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
      // Mask account number for security on response list (unless exporting)
      if (!isExport && decrypted.accountNumber && decrypted.accountNumber.length > 4) {
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

// @route   GET /api/bank-verification/sample-template
// @desc    Download a valid sample Excel template for bank verification
// @access  Private
router.get('/sample-template', protect, checkModuleAccess('bank-verification'), async (req, res) => {
  try {
    const rows = [
      ['ifsc', 'accountNumber'],
      ['HDFC0001234', '123456789012'],
      ['ICIC0005678', '987654321098']
    ];
    const wb = XLSX.utils.book_new();
    const ws = XLSX.utils.aoa_to_sheet(rows);
    XLSX.utils.book_append_sheet(wb, ws, 'Sheet1');
    const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
    res.setHeader(
      'Content-Type',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );
    res.setHeader(
      'Content-Disposition',
      'attachment; filename="sample_bank_verification.xlsx"'
    );
    res.send(Buffer.from(buf));
  } catch (error) {
    logger.error('Error generating Bank verification sample template:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to generate sample template'
    });
  }
});

module.exports = router;

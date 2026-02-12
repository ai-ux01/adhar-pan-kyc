const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const mongoose = require('mongoose');
const XLSX = require('xlsx');
const { protect } = require('../middleware/auth');
const PanKyc = require('../models/PanKyc');
const { logPanKycEvent } = require('../services/auditService');
const logger = require('../utils/logger');
const { verifyPAN } = require('../services/panVerificationService');

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '../../uploads/pan-kyc');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: async (req, file, cb) => {
    const originalName = path.parse(file.originalname).name;
    const extension = path.extname(file.originalname);
    const timestamp = Date.now();
    const randomSuffix = Math.random().toString(36).substring(2, 8);
    cb(null, `${originalName}_${timestamp}_${randomSuffix}${extension}`);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['.xlsx', '.xls'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedTypes.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Only Excel files (.xlsx, .xls) are allowed'));
    }
  }
});

// Get all PAN KYC batches for the user
router.get('/batches', protect, async (req, res) => {
  try {
    const batches = await PanKyc.aggregate([
      { $match: { userId: new mongoose.Types.ObjectId(req.user.id) } },
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
    logger.error('Error fetching PAN KYC batches:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch batches' });
  }
});

// Get batch details
router.get('/batch/:batchId', protect, async (req, res) => {
  try {
    const { batchId } = req.params;
    const records = await PanKyc.find({
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
        const tempDoc = new PanKyc(record);
        return tempDoc.decryptData();
      } catch (error) {
        logger.error('Error decrypting record:', error);
        return record;
      }
    });

    const stats = await PanKyc.aggregate([
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

// Upload PAN KYC file
router.post('/upload', protect, upload.single('file'), async (req, res) => {
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
      return res.status(400).json({
        success: false,
        message: 'No data found in the Excel file'
      });
    }

    // Validate required columns
    const requiredColumns = ['panNumber', 'name', 'dateOfBirth'];
    const firstRow = data[0];
    
    const columnMapping = {
      'panNumber': ['panNumber', 'PAN No', 'PAN', 'pan', 'PANNumber', 'pan_number', 'PAN No.'],
      'name': ['name', 'Name', 'NAME', 'fullName', 'Full Name', 'full_name', 'FULL NAME'],
      'dateOfBirth': ['dateOfBirth', 'DOB', 'dob', 'Date of Birth', 'dateOfBirth', 'birthDate', 'Birth Date', 'BIRTH DATE']
    };
    
    const missingColumns = [];
    const columnMap = {};
    
    requiredColumns.forEach(requiredCol => {
      const possibleNames = columnMapping[requiredCol];
      let found = false;
      
      for (const possibleName of possibleNames) {
        if (firstRow.hasOwnProperty(possibleName)) {
          columnMap[requiredCol] = possibleName;
          found = true;
          break;
        }
      }
      
      if (!found) {
        missingColumns.push(requiredCol);
      }
    });
    
    if (missingColumns.length > 0) {
      return res.status(400).json({
        success: false,
        message: `Missing required columns: ${missingColumns.join(', ')}`
      });
    }

    // Create batch ID
    const batchId = `${req.file.originalname.split('.')[0]}_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    
    // Process and save records
    const records = [];
    for (const row of data) {
      const record = new PanKyc({
        userId: req.user.id,
        batchId: batchId,
        panNumber: row[columnMap.panNumber],
        name: row[columnMap.name],
        dateOfBirth: row[columnMap.dateOfBirth],
        status: 'pending'
      });
      
      await record.save();
      records.push(record);
    }

    // Clean up uploaded file
    fs.unlinkSync(req.file.path);

    res.json({
      success: true,
      message: `Successfully uploaded ${records.length} records`,
      data: {
        batchId,
        totalRecords: records.length,
        batchName: req.file.originalname
      }
    });

  } catch (error) {
    logger.error('Error uploading file:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to upload file',
      error: error.message
    });
  }
});

// Process batch verification with REAL Sandbox API
router.post('/batch/:batchId/process', protect, async (req, res) => {
  try {
    const { batchId } = req.params;
    
    // Get pending records
    const pendingRecords = await PanKyc.find({
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
        // Use real Sandbox API for verification
        const startTime = Date.now();
        
        // Decrypt the data before calling the API
        const decryptedRecord = record.decryptData();
        
        // Call real PAN verification API with decrypted data
        const verificationResult = await verifyPAN(decryptedRecord.panNumber, decryptedRecord.name, decryptedRecord.dateOfBirth);
        
        const processingTime = Date.now() - startTime;
        
        // Update record with real verification result
        record.status = verificationResult.valid ? 'verified' : 'rejected';
        record.isProcessed = true;
        record.processedAt = new Date();
        record.processingTime = processingTime;
        record.verificationDetails = {
          apiResponse: verificationResult.details.apiResponse,
          verificationDate: new Date(),
          remarks: verificationResult.message,
          source: verificationResult.details.source,
          confidence: verificationResult.details.confidence,
          dataMatch: verificationResult.details.dataMatch,
          nameMatch: verificationResult.details.nameMatch,
          dobMatch: verificationResult.details.dobMatch,
          category: verificationResult.details.category,
          aadhaarSeedingStatus: verificationResult.details.aadhaarSeedingStatus,
          transactionId: verificationResult.details.transactionId
        };
        
        await record.save();
        
        results.push({
          recordId: record._id,
          status: record.status,
          result: verificationResult,
          processingTime: processingTime
        });

        // Log verification event
        await logPanKycEvent('pan_kyc_verification', req.user.id, {
          recordId: record._id,
          batchId: batchId,
          status: record.status,
          processingTime: processingTime
        }, req);

        // Add delay between API calls to avoid overwhelming the Sandbox API
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

// Single KYC verification endpoint with REAL Sandbox API
router.post('/verify-single', protect, async (req, res) => {
  try {
    const { panNumber, name, dateOfBirth } = req.body;

    if (!panNumber || !name || !dateOfBirth) {
      return res.status(400).json({
        success: false,
        message: 'PAN Number, Name, and Date of Birth are required'
      });
    }

    // Validate PAN format
    const panRegex = /^[A-Z]{5}[0-9]{4}[A-Z]{1}$/;
    if (!panRegex.test(panNumber.toUpperCase())) {
      return res.status(400).json({
        success: false,
        message: 'Invalid PAN number format'
      });
    }

    // Create a temporary record for verification
    const tempRecord = new PanKyc({
      userId: req.user.id,
      batchId: 'SINGLE_KYC_' + Date.now(),
      panNumber: panNumber.toUpperCase(),
      name: name.trim(),
      dateOfBirth: dateOfBirth.trim(),
      status: 'pending'
    });

    // Use real Sandbox API for verification
    const startTime = Date.now();
    const verificationResult = await verifyPAN(panNumber, name, dateOfBirth);
    
    // Update record with real verification result
    tempRecord.status = verificationResult.valid ? 'verified' : 'rejected';
    tempRecord.verificationDetails = {
      apiResponse: verificationResult.details.apiResponse,
      verificationDate: new Date(),
      remarks: verificationResult.message,
      source: verificationResult.details.source,
      confidence: verificationResult.details.confidence,
      dataMatch: verificationResult.details.dataMatch,
      nameMatch: verificationResult.details.nameMatch,
      dobMatch: verificationResult.details.dobMatch,
      category: verificationResult.details.category,
      aadhaarSeedingStatus: verificationResult.details.aadhaarSeedingStatus,
      transactionId: verificationResult.details.transactionId
    };
    tempRecord.processedAt = new Date();
    tempRecord.processingTime = Date.now() - startTime;
    
    await tempRecord.save();

    // Log verification event
    await logPanKycEvent('single_kyc_verified', req.user.id, {
      panNumber: tempRecord.panNumber,
      name: tempRecord.name,
      status: tempRecord.status
    }, req);

    res.json({
      success: true,
      message: 'KYC verification completed',
      data: {
        panNumber: tempRecord.panNumber,
        name: tempRecord.name,
        dateOfBirth: tempRecord.dateOfBirth,
        status: tempRecord.status,
        verificationDetails: tempRecord.verificationDetails,
        processedAt: tempRecord.processedAt,
        processingTime: tempRecord.processingTime
      }
    });

  } catch (error) {
    logger.error('Error in single KYC verification:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to verify KYC'
    });
  }
});

// Test Sandbox API route
router.get('/test-sandbox', async (req, res) => {
  try {
    console.log('🧪 Testing Sandbox API connection...');
    
    // 1️⃣ Authenticate
    const authRes = await fetch("https://api.sandbox.co.in/authenticate", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": process.env.SANDBOX_API_KEY,
        "x-api-secret": process.env.SANDBOX_API_SECRET,
      },
    });

    const authData = await authRes.json();
    console.log('🔐 TEST AUTH RESPONSE:', JSON.stringify(authData, null, 2));

    if (!authRes.ok) {
      return res.status(authRes.status).json({
        error: 'Authentication failed',
        auth_response: authData
      });
    }

    const accessToken = authData.access_token || authData.data?.access_token;
    console.log('🔑 TEST Access Token:', accessToken);

    // 2️⃣ Test verification with sample data
    const testPayload = {
      "@entity": "in.co.sandbox.kyc.pan_verification.request",
      pan: "IXDPK9199A",
      name_as_per_pan: "NEHA KANWAR",
      date_of_birth: "29/09/2003",
      consent: "Y",
      reason: "KYC verification test",
    };

    console.log('📤 TEST VERIFY PAYLOAD:', JSON.stringify(testPayload, null, 2));

    const verifyRes = await fetch("https://api.sandbox.co.in/kyc/pan/verify", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "authorization": accessToken,
        "x-api-key": process.env.SANDBOX_API_KEY,
        "x-accept-cache": "true",
      },
      body: JSON.stringify(testPayload),
    });

    console.log('📡 TEST HTTP Status:', verifyRes.status, verifyRes.statusText);

    const verifyData = await verifyRes.json();
    console.log('✅ TEST VERIFY RESPONSE:', JSON.stringify(verifyData, null, 2));

    res.json({
      success: true,
      auth_response: authData,
      verify_response: verifyData,
      http_status: verifyRes.status,
      message: 'Test completed - check console for detailed logs'
    });

  } catch (error) {
    console.error('❌ TEST ERROR:', error);
    res.status(500).json({
      error: 'Test failed',
      message: error.message
    });
  }
});

module.exports = router;

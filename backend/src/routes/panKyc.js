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

// Helper function to convert Excel serial number to date string
function excelSerialToDate(serial) {
  if (!serial || isNaN(serial)) return null;
  
  try {
    // Use XLSX library's built-in date parsing
    const date = XLSX.SSF.parse_date_code(serial);
    if (date) {
      // Format as DD/MM/YYYY
      const day = String(date.d).padStart(2, '0');
      const month = String(date.m).padStart(2, '0');
      const year = date.y;
      return `${day}/${month}/${year}`;
    }
  } catch (error) {
    console.error('Error parsing Excel date:', error);
  }
  
  return null;
}

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
      { 
        $match: { 
          userId: new mongoose.Types.ObjectId(req.user.id),
          // Exclude single KYC verification records (they start with SINGLE_KYC_)
          batchId: { $not: { $regex: /^SINGLE_KYC_/ } }
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
    logger.error('Error fetching PAN KYC batches:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch batches' });
  }
});

// Get all records for a user
router.get('/records', protect, async (req, res) => {
  const startTime = Date.now();
  let requestTimeout;
  
  try {
    // Set a timeout to prevent hanging requests (30 seconds)
    requestTimeout = setTimeout(() => {
      if (!res.headersSent) {
        logger.warn('Request timeout for /pan-kyc/records');
        res.status(504).json({
          success: false,
          message: 'Request timeout. Please try again with pagination (use ?page=1&limit=50)',
          error: 'Request took too long to process'
        });
      }
    }, 30000); // 30 second timeout

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50; // Reduced default to 50 for better performance
    const maxLimit = 500; // Reduced max limit
    const actualLimit = Math.min(limit, maxLimit);
    const skip = (page - 1) * actualLimit;
    const search = req.query.search || '';
    const status = req.query.status || '';
    const sortBy = req.query.sortBy || 'createdAt';
    const sortOrder = req.query.sortOrder || 'desc';

    logger.info(`Fetching PAN KYC records: page=${page}, limit=${actualLimit}, userId=${req.user.id}`);

    // Build query
    let query = { userId: req.user.id };
    
    // Add search filter
    if (search) {
      const searchRegex = new RegExp(search, 'i');
      query.$or = [
        { panNumber: searchRegex },
        { name: searchRegex },
        { fatherName: searchRegex }
      ];
    }
    
    // Add status filter
    if (status) {
      query.status = status;
    }

    // Get total count for pagination (with timeout protection)
    const totalRecords = await PanKyc.countDocuments(query).maxTimeMS(5000);
    const totalPages = Math.ceil(totalRecords / actualLimit);

    // Build sort object
    const sortObj = {};
    sortObj[sortBy] = sortOrder === 'asc' ? 1 : -1;

    // Get paginated records (with timeout protection)
    const records = await PanKyc.find(query)
      .sort(sortObj)
      .skip(skip)
      .limit(actualLimit)
      .maxTimeMS(10000) // 10 second timeout for query
      .lean();

    logger.info(`Found ${records.length} records, starting decryption...`);

    // Decrypt sensitive data in parallel for better performance
    const decryptedRecords = await Promise.all(
      records.map(async (record) => {
        try {
          // Create a temporary PanKyc instance to use the decryptData method
          const tempRecord = new PanKyc(record);
          return tempRecord.decryptData();
        } catch (error) {
          logger.error(`Decryption error for record ${record._id}:`, error.message);
          // Return original record with encrypted fields marked
          return {
            ...record,
            panNumber: record.panNumber ? '[ENCRYPTED]' : '',
            name: record.name ? '[ENCRYPTED]' : '',
            dateOfBirth: record.dateOfBirth ? '[ENCRYPTED]' : '',
            fatherName: record.fatherName ? '[ENCRYPTED]' : ''
          };
        }
      })
    );

    const processingTime = Date.now() - startTime;
    logger.info(`Records fetched and decrypted in ${processingTime}ms`);

    // Clear timeout since we're responding
    clearTimeout(requestTimeout);

    res.json({
      success: true,
      data: decryptedRecords,
      pagination: {
        currentPage: page,
        totalPages: totalPages,
        totalRecords: totalRecords,
        hasNext: page < totalPages,
        hasPrev: page > 1,
        limit: actualLimit
      },
      processingTime: processingTime
    });
  } catch (error) {
    // Clear timeout on error
    if (requestTimeout) {
      clearTimeout(requestTimeout);
    }
    
    logger.error('Error fetching PAN KYC records:', error);
    
    // Don't send response if already sent
    if (!res.headersSent) {
      res.status(500).json({
        success: false,
        message: 'Failed to fetch records',
        error: error.message
      });
    }
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
      'panNumber': ['panNumber', 'PAN No', 'PAN', 'pan', 'PANNumber', 'pan_number', 'PAN No.', 'PAN No'],
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
      // Validate that required fields are present and not empty
      const panNumber = row[columnMap.panNumber];
      const name = row[columnMap.name];
      const dateOfBirthRaw = row[columnMap.dateOfBirth];
      
      // Skip rows with missing or empty required fields
      if (!panNumber || !name || panNumber.toString().trim() === '' || name.toString().trim() === '') {
        logger.warn(`Skipping row with missing required fields:`, { panNumber, name, dateOfBirth: dateOfBirthRaw });
        continue;
      }
      
      // Convert date of birth - handle both Excel serial numbers and date strings
      let dateOfBirth = null;
      if (dateOfBirthRaw !== undefined && dateOfBirthRaw !== null) {
        if (typeof dateOfBirthRaw === 'number' && dateOfBirthRaw > 1000) { // Excel serial number (reasonable range)
          dateOfBirth = excelSerialToDate(dateOfBirthRaw);
        } else if (typeof dateOfBirthRaw === 'string' && dateOfBirthRaw.trim() !== '') {
          dateOfBirth = dateOfBirthRaw.trim();
        }
      }
      
      // Skip rows with empty or missing date of birth
      if (!dateOfBirth || dateOfBirth.trim() === '') {
        logger.warn(`Skipping row with missing date of birth:`, { panNumber, name, dateOfBirth: dateOfBirthRaw });
        continue;
      }
      
      const record = new PanKyc({
        userId: req.user.id,
        batchId: batchId,
        panNumber: panNumber.toString().trim(),
        name: name.toString().trim(),
        dateOfBirth: dateOfBirth,
        status: 'pending'
      });
      
      await record.save();
      records.push(record);
    }

    // Check if any valid records were processed
    if (records.length === 0) {
      // Clean up uploaded file
      fs.unlinkSync(req.file.path);
      
      return res.status(400).json({
        success: false,
        message: 'No valid records found in the file. Please check that all required columns (PAN Number, Name) have data.',
        data: {
          totalRows: data.length,
          skippedRows: data.length
        }
      });
    }

    // Clean up uploaded file
    fs.unlinkSync(req.file.path);

    // Log successful upload
    logger.info(`Successfully uploaded PAN KYC file: ${req.file.originalname}`, {
      userId: req.user.id,
      batchId,
      totalRecords: records.length,
      totalRows: data.length,
      skippedRows: data.length - records.length
    });

    // Log the upload event for admin stats
    await logPanKycEvent('pan_kyc_upload', req.user.id, {
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
        record.status = verificationResult.valid && verificationResult.details.nameMatch && verificationResult.details.dobMatch ? 'verified' : 'rejected';
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

// Batch record verification endpoint (frontend calls this with recordIds)
router.post('/verify', protect, async (req, res) => {
  // Set a longer timeout for batch processing
  req.setTimeout(300000); // 5 minutes timeout
  res.setTimeout(300000); // 5 minutes timeout
  try {
    console.log('🔍 Received verification request:', {
      body: req.body,
      contentType: req.get('Content-Type'),
      user: req.user.id
    });

          // Check if this is a batch verification request
      if (req.body.recordIds && Array.isArray(req.body.recordIds)) {
        console.log('📦 Processing batch verification for records:', req.body.recordIds.length, 'records');
        
        const results = [];
        const totalRecords = req.body.recordIds.length;
        
        for (let i = 0; i < req.body.recordIds.length; i++) {
          const recordId = req.body.recordIds[i];
          console.log(`🔄 Processing record ${i + 1}/${totalRecords}: ${recordId}`);
        try {
          // Find the record
          const record = await PanKyc.findOne({
            _id: recordId,
            userId: req.user.id
          });

          if (!record) {
            results.push({
              recordId,
              status: 'error',
              error: 'Record not found'
            });
            continue;
          }

          // Use real Sandbox API for verification
          const startTime = Date.now();
          
          // Decrypt the data before calling the API
          const decryptedRecord = record.decryptData();
          
          // Call real PAN verification API with decrypted data
          const verificationResult = await verifyPAN(decryptedRecord.panNumber, decryptedRecord.name, decryptedRecord.dateOfBirth);
          
          const processingTime = Date.now() - startTime;
          
          // Update record with real verification result
          record.status = verificationResult.valid && verificationResult.details.nameMatch && verificationResult.details.dobMatch ? 'verified' : 'rejected';
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
            status: record.status,
            processingTime: processingTime
          }, req);

          // Reduced delay between API calls for better performance
          await new Promise(resolve => setTimeout(resolve, 200));

        } catch (error) {
          console.error(`❌ Error processing record ${recordId}:`, error);
          
          results.push({
            recordId,
            status: 'error',
            error: error.message
          });
        }
      }

      return res.json({
        success: true,
        message: `Processed ${results.length} records`,
        data: {
          results,
          summary: {
            total: results.length,
            verified: results.filter(r => r.status === 'verified').length,
            rejected: results.filter(r => r.status === 'rejected').length,
            error: results.filter(r => r.status === 'error').length
          }
        }
      });
    }

        // If not batch verification, proceed with single verification
    const { panNumber, name, dateOfBirth } = req.body;

    // Log the extracted values
    console.log('📋 Extracted values:', { panNumber, name, dateOfBirth });

    if (!panNumber || !name || !dateOfBirth) {
      console.log('❌ Missing required fields:', { 
        hasPanNumber: !!panNumber, 
        hasName: !!name, 
        hasDateOfBirth: !!dateOfBirth 
      });
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
    tempRecord.status = verificationResult.valid && verificationResult.details.nameMatch && verificationResult.details.dobMatch ? 'verified' : 'rejected';
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

// Single KYC verification endpoint with REAL Sandbox API (alias for /verify)
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
    tempRecord.status = verificationResult.valid && verificationResult.details.nameMatch && verificationResult.details.dobMatch ? 'verified' : 'rejected';
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

    // Decrypt the data before sending response
    let decryptedRecord;
    try {
      decryptedRecord = tempRecord.decryptData();
    } catch (error) {
      console.error('❌ Decryption error:', error.message);
      // Fallback to original input data if decryption fails
      decryptedRecord = {
        panNumber: panNumber.toUpperCase(), // Use original input
        name: name.trim(),                  // Use original input
        dateOfBirth: dateOfBirth.trim(),    // Use original input
        verificationDetails: tempRecord.verificationDetails
      };
    }

    // Log verification event
    await logPanKycEvent('single_kyc_verified', req.user.id, {
      panNumber: decryptedRecord.panNumber,
      name: decryptedRecord.name,
      status: tempRecord.status
    }, req);

    // Set appropriate message based on verification status
    const statusMessage = tempRecord.status === 'verified' 
      ? 'KYC verification completed successfully' 
      : 'KYC verification failed - data mismatch detected';

    res.json({
      success: true,
      message: statusMessage,
      data: {
        panNumber: decryptedRecord.panNumber,
        name: decryptedRecord.name,
        dateOfBirth: decryptedRecord.dateOfBirth,
        status: tempRecord.status,
        verificationDetails: decryptedRecord.verificationDetails,
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

// Delete batch and all its records
router.delete('/batch/:batchId', protect, async (req, res) => {
  try {
    const { batchId } = req.params;
    
    // Prevent deletion of single KYC verification records
    if (batchId.startsWith('SINGLE_KYC_')) {
      return res.status(400).json({
        success: false,
        message: 'Cannot delete single KYC verification records'
      });
    }
    
    // Find all records for this batch that belong to the user
    const records = await PanKyc.find({
      userId: new mongoose.Types.ObjectId(req.user.id),
      batchId: batchId
    });

    if (records.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Batch not found or access denied'
      });
    }

    // Delete all records for this batch
    const deleteResult = await PanKyc.deleteMany({
      userId: new mongoose.Types.ObjectId(req.user.id),
      batchId: batchId
    });

    // Log deletion event
    await logPanKycEvent('batch_deleted', req.user.id, {
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

module.exports = router;

